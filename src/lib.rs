use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::Path;

use anyhow::{bail, Context, Result};
use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter, Instruction, Mnemonic, OpKind};
use object::{File, Object, ObjectSection, ObjectSymbol, RelocationTarget, SectionKind, SymbolKind};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;

pub mod tui;

/* represents an executable section in memory (e.g. .text, .plt) stored as raw bytes for runtime disassembly */
#[derive(Debug, Clone)]
pub struct ExecutableSection {
    /* section header name, such as ".text" or ".plt" */
    pub name: String,
    /* base virtual address where this section is loaded in memory */
    pub address: u64,
    /* raw binary machine code bytes extracted from the ELF file */
    pub data: Vec<u8>,
}

/* a single disassembled machine instruction decoded by iced-x86 with metadata for call graph analysis */
#[derive(Debug, Clone)]
pub struct DisassembledLine {
    /* virtual instruction pointer (IP) address where this instruction resides */
    pub ip: u64,
    /* raw machine code bytes corresponding to this decoded instruction */
    pub bytes: Vec<u8>,
    /* human-readable assembly text formatted in Intel syntax, e.g. "call 0x115b" or "push rbp" */
    pub instruction_text: String,
    /* flag indicating whether this instruction is a subroutine call (e.g. direct CALL) */
    pub is_call: bool,
    /* target virtual address if this is a direct CALL instruction */
    pub call_target: Option<u64>,
    /* resolved human-readable symbol name of the callee function, if found in symbol tables */
    pub target_symbol: Option<String>,
}

/* represents a function or trampoline stub node in the call graph */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionNode {
    /* demangled or human-friendly symbol name (e.g. "my_crate::my_func" instead of "_RNv...") */
    pub name: String,
    /* raw mangled symbol name directly from the ELF symbol table */
    pub raw_name: String,
    /* virtual start address in memory where the function code begins */
    pub address: u64,
    /* size in bytes of the function code */
    pub size: u64,
    /* true if this node is a PLT (Procedure Linkage Table) trampoline stub for dynamically imported symbols */
    pub is_plt: bool,
}

impl fmt::Display for FunctionNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_plt {
            write!(f, "{} [PLT stub at 0x{:x}]", self.name, self.address)
        } else if self.size > 0 {
            write!(
                f,
                "{} (0x{:x}..0x{:x}, {} bytes)",
                self.name,
                self.address,
                self.address + self.size,
                self.size
            )
        } else {
            write!(f, "{} (0x{:x})", self.name, self.address)
        }
    }
}

/* information associated with a directed call edge in the petgraph DiGraph */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEdge {
    /* virtual address of the CALL instruction where the caller invokes the callee */
    pub call_site: u64,
}

impl fmt::Display for CallEdge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "call site: 0x{:x}", self.call_site)
    }
}

/* address range entry [start, end) used to resolve any virtual address to its enclosing symbol */
#[derive(Debug, Clone)]
pub struct SymbolRange {
    /* demangled symbol name */
    pub name: String,
    /* raw mangled symbol name */
    pub raw_name: String,
    /* inclusive start virtual address */
    pub start: u64,
    /* exclusive end virtual address */
    pub end: u64,
    /* whether this symbol range belongs to a PLT trampoline stub */
    pub is_plt: bool,
}

/* an ordered lookup map storing contiguous virtual address ranges [start, end) for O(log N) symbol resolution */
#[derive(Debug, Default, Clone)]
pub struct SymbolMap {
    /* ordered map keyed by start address to allow range search queries via BTreeMap::range */
    ranges: BTreeMap<u64, SymbolRange>,
}

impl SymbolMap {
    /* creates an empty symbol range lookup map */
    pub fn new() -> Self {
        Self {
            ranges: BTreeMap::new(),
        }
    }

    /* inserts an address range entry into the lookup map */
    pub fn insert(&mut self, range: SymbolRange) {
        self.ranges.insert(range.start, range);
    }

    /* resolves any virtual address back to its enclosing symbol range; matches exact start address first, then checks if addr falls in [start, end) */
    pub fn resolve(&self, addr: u64) -> Option<&SymbolRange> {
        /* find the latest function starting at or before the queried address */
        if let Some((&start, range)) = self.ranges.range(..=addr).next_back() {
            if addr == start || addr < range.end {
                return Some(range);
            }
        }
        None
    }

    /* returns an iterator over all mapped symbol ranges */
    pub fn iter(&self) -> impl Iterator<Item = &SymbolRange> {
        self.ranges.values()
    }

    /* returns the number of mapped symbol ranges */
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    /* returns true if no symbol ranges are stored */
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

/* strips compiler disambiguators such as "[c0acaeba6ab4c2e0]" from Rust v0 demangled symbol names */
pub fn strip_disambiguators(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut in_bracket = false;
    for c in s.chars() {
        if c == '[' {
            in_bracket = true;
        } else if c == ']' {
            in_bracket = false;
        } else if !in_bracket {
            result.push(c);
        }
    }
    result
}

/* the reconstructed call graph backed by petgraph::graph::DiGraph */
pub struct CallGraph {
    /* directed graph where nodes are functions or PLT stubs, and edges represent direct CALL instructions */
    pub graph: DiGraph<FunctionNode, CallEdge>,
    /* map from virtual start address to node index in the DiGraph */
    pub node_indices: HashMap<u64, NodeIndex>,
    /* interval map for resolving call target addresses back to symbols */
    pub symbol_map: SymbolMap,
    /* executable binary sections (.text, .plt, etc.) saved to disassemble function bytes on demand */
    pub exec_sections: Vec<ExecutableSection>,
}

impl CallGraph {
    /* retrieves the raw machine code byte slice for a function given its start address and size */
    pub fn get_function_bytes(&self, addr: u64, size: u64) -> Option<&[u8]> {
        for sec in &self.exec_sections {
            if addr >= sec.address && addr < sec.address + sec.data.len() as u64 {
                let offset = (addr - sec.address) as usize;
                let max_avail = sec.data.len() - offset;
                let len = if size > 0 {
                    (size as usize).min(max_avail)
                } else {
                    max_avail.min(256)
                };
                return Some(&sec.data[offset..offset + len]);
            }
        }
        None
    }

    /* disassembles a function's instructions using iced-x86, identifying direct CALL instructions and resolving targets */
    pub fn disassemble_function(&self, addr: u64, size: u64) -> Vec<DisassembledLine> {
        let Some(bytes) = self.get_function_bytes(addr, size) else {
            return Vec::new();
        };

        /* iced-x86 decoder configured for 64-bit x86 machine code */
        let mut decoder = Decoder::with_ip(64, bytes, addr, DecoderOptions::NONE);
        let mut formatter = IntelFormatter::new();
        let mut output = String::new();
        let mut instr = Instruction::default();
        let mut lines = Vec::new();

        while decoder.can_decode() {
            let ip = decoder.ip();
            let start_offset = (ip.saturating_sub(addr)) as usize;
            decoder.decode_out(&mut instr);
            let instr_len = instr.len();

            let instr_bytes = if start_offset < bytes.len() {
                let end = (start_offset + instr_len).min(bytes.len());
                bytes[start_offset..end].to_vec()
            } else {
                Vec::new()
            };

            output.clear();
            formatter.format(&instr, &mut output);

            let is_call = instr.mnemonic() == Mnemonic::Call;
            let mut call_target = None;
            let mut target_symbol = None;

            if is_call {
                /* check if operand is a direct relative branch (near branch) rather than an indirect register/memory jump */
                if matches!(
                    instr.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                ) {
                    let target = instr.near_branch_target();
                    call_target = Some(target);
                    if let Some(sym) = self.symbol_map.resolve(target) {
                        target_symbol = Some(sym.name.clone());
                    }
                }
            }

            lines.push(DisassembledLine {
                ip,
                bytes: instr_bytes,
                instruction_text: output.clone(),
                is_call,
                call_target,
                target_symbol,
            });
        }

        lines
    }

    /* retrieves all node indices matching a query; supports exact match, suffix match (e.g. "main" matching "crate::main"), and substring fallback */
    pub fn find_nodes_by_name(&self, query: &str) -> Vec<NodeIndex> {
        let clean_query = strip_disambiguators(query);
        let mut exact_matches = Vec::new();
        let mut suffix_matches = Vec::new();
        let mut substring_matches = Vec::new();

        for idx in self.graph.node_indices() {
            let node = &self.graph[idx];
            let clean_name = strip_disambiguators(&node.name);

            if node.name == query || node.raw_name == query || clean_name == clean_query {
                exact_matches.push(idx);
            } else if clean_name.ends_with(&format!("::{}", clean_query)) {
                suffix_matches.push(idx);
            } else if clean_name.contains(&clean_query) || node.raw_name.contains(query) {
                substring_matches.push(idx);
            }
        }

        /* if searching for "main", combine both runtime C "main" and Rust user "*::main" */
        if query == "main" || clean_query == "main" {
            let mut all_main = exact_matches.clone();
            for &idx in &suffix_matches {
                if !all_main.contains(&idx) {
                    all_main.push(idx);
                }
            }
            if !all_main.is_empty() {
                return all_main;
            }
        }

        if !exact_matches.is_empty() {
            exact_matches
        } else if !suffix_matches.is_empty() {
            suffix_matches
        } else {
            substring_matches
        }
    }

    /* returns the outgoing direct callees for a given node index, sorted by call site virtual address */
    pub fn outgoing_calls(&self, node_idx: NodeIndex) -> Vec<(&FunctionNode, &CallEdge)> {
        let mut callees = Vec::new();
        for edge_ref in self.graph.edges_directed(node_idx, Direction::Outgoing) {
            let callee_node = &self.graph[edge_ref.target()];
            let edge = edge_ref.weight();
            callees.push((callee_node, edge));
        }
        /* sort by call site address for deterministic and readable output */
        callees.sort_by_key(|(_, edge)| edge.call_site);
        callees
    }

    /* formats the adjacency list for a given node index into human-readable text */
    pub fn format_adjacency_list(&self, node_idx: NodeIndex) -> String {
        let caller = &self.graph[node_idx];
        let callees = self.outgoing_calls(node_idx);

        let mut out = String::new();
        out.push_str(&format!("Function: {}\n", caller.name));
        out.push_str(&format!("  Virtual Address: 0x{:x}\n", caller.address));
        if caller.size > 0 {
            out.push_str(&format!("  Size: {} bytes (0x{:x})\n", caller.size, caller.size));
        }
        out.push_str(&format!("  Direct Callees ({}):\n", callees.len()));

        if callees.is_empty() {
            out.push_str("    (none)\n");
        } else {
            for (callee, edge) in callees {
                out.push_str(&format!(
                    "    -> {} [call site: 0x{:x}]\n",
                    callee, edge.call_site
                ));
            }
        }
        out
    }

    /* exports the reconstructed call graph in Graphviz DOT format for external visualization */
    pub fn to_dot(&self) -> String {
        let mut dot = String::new();
        dot.push_str("digraph CallGraph {\n");
        dot.push_str("  node [shape=box, fontname=\"Courier\"];\n");
        dot.push_str("  edge [fontname=\"Courier\", fontsize=10];\n");

        for idx in self.graph.node_indices() {
            let node = &self.graph[idx];
            let label = if node.is_plt {
                format!("{}\\n[PLT stub 0x{:x}]", node.name, node.address)
            } else {
                format!("{}\\n0x{:x}", node.name, node.address)
            };
            let style = if node.is_plt {
                ", style=dashed, color=gray"
            } else {
                ""
            };
            dot.push_str(&format!(
                "  \"node_{}\" [label=\"{}\"{}];\n",
                idx.index(),
                label.replace('"', "\\\""),
                style
            ));
        }

        for edge_ref in self.graph.edge_references() {
            let src = edge_ref.source();
            let dst = edge_ref.target();
            let edge = edge_ref.weight();
            dot.push_str(&format!(
                "  \"node_{}\" -> \"node_{}\" [label=\"0x{:x}\"];\n",
                src.index(),
                dst.index(),
                edge.call_site
            ));
        }

        dot.push_str("}\n");
        dot
    }
}

/* builder that parses an x86_64 ELF binary and reconstructs its function call graph */
pub struct ElfCallGraphBuilder<'a> {
    file: File<'a>,
}

impl<'a> ElfCallGraphBuilder<'a> {
    /* loads and validates an x86_64 ELF binary from a raw byte slice */
    pub fn new(data: &'a [u8]) -> Result<Self> {
        let file = File::parse(data).context("Failed to parse binary file format")?;

        if file.format() != object::BinaryFormat::Elf {
            bail!("Input file is not an ELF binary (format: {:?})", file.format());
        }

        if file.architecture() != object::Architecture::X86_64 {
            bail!(
                "Architecture {:?} is not supported; expected x86_64",
                file.architecture()
            );
        }

        Ok(Self { file })
    }

    /* builds the full CallGraph by parsing symbols, resolving PLT stubs, disassembling .text, and building the DiGraph */
    pub fn build(self) -> Result<CallGraph> {
        let mut symbol_map = SymbolMap::new();

        /* 1. resolve dynamic symbols and GOT relocations to map PLT trampoline stubs */
        let plt_stubs = self.resolve_plt_stubs()?;
        for stub in &plt_stubs {
            symbol_map.insert(SymbolRange {
                name: stub.name.clone(),
                raw_name: stub.raw_name.clone(),
                start: stub.address,
                end: stub.address + stub.size,
                is_plt: true,
            });
        }

        /* 2. locate .text section containing compiled machine code */
        let text_section = self
            .file
            .section_by_name(".text")
            .context("Binary does not contain a .text section")?;
        let text_addr = text_section.address();
        let text_size = text_section.size();
        let text_end = text_addr + text_size;
        let text_bytes = text_section.data().context("Failed to read .text section data")?;

        /* collect defined function symbols from .symtab and .dynsym */
        let mut raw_funcs: BTreeMap<u64, (String, String, u64)> = BTreeMap::new();

        /* helper closure to filter STT_FUNC symbols (SymbolKind::Text) and demangle their names */
        let mut process_symbol = |sym: &object::read::Symbol| {
            if sym.kind() == SymbolKind::Text && !sym.is_undefined() {
                let addr = sym.address();
                if addr != 0 {
                    let raw_name = sym.name().unwrap_or("").to_string();
                    let demangled = rustc_demangle::demangle(&raw_name).to_string();
                    let size = sym.size();

                    /* insert or refine entry if an explicit non-zero size is discovered */
                    raw_funcs
                        .entry(addr)
                        .and_modify(|existing| {
                            if existing.2 == 0 && size > 0 {
                                existing.2 = size;
                            }
                        })
                        .or_insert((demangled, raw_name, size));
                }
            }
        };

        /* parse .symtab table for local and global static symbols */
        for sym in self.file.symbols() {
            process_symbol(&sym);
        }

        /* parse .dynsym table for dynamic and exported symbols */
        for sym in self.file.dynamic_symbols() {
            process_symbol(&sym);
        }

        /* calculate effective function ranges [addr, addr + effective_size); if st_size is 0 (common in handwritten assembly or stubs), interpolate size up to next symbol start or section end */
        let sorted_addrs: Vec<u64> = raw_funcs.keys().copied().collect();
        for (i, &addr) in sorted_addrs.iter().enumerate() {
            let (demangled, raw_name, explicit_size) = &raw_funcs[&addr];
            let effective_size = if *explicit_size > 0 {
                *explicit_size
            } else if i + 1 < sorted_addrs.len() {
                sorted_addrs[i + 1].saturating_sub(addr)
            } else if addr >= text_addr && addr < text_end {
                text_end.saturating_sub(addr)
            } else {
                16 /* minimum reasonable fallback size for single-instruction stubs */
            };

            symbol_map.insert(SymbolRange {
                name: demangled.clone(),
                raw_name: raw_name.clone(),
                start: addr,
                end: addr + effective_size,
                is_plt: false,
            });
        }

        /* 3. initialize petgraph DiGraph and index lookup map */
        let mut graph = DiGraph::<FunctionNode, CallEdge>::new();
        let mut node_indices = HashMap::<u64, NodeIndex>::new();

        /* helper closure to retrieve existing NodeIndex or create a new graph node */
        let get_or_insert_node = |graph: &mut DiGraph<FunctionNode, CallEdge>,
                                  node_indices: &mut HashMap<u64, NodeIndex>,
                                  addr: u64,
                                  symbol_map: &SymbolMap|
         -> NodeIndex {
            if let Some(&idx) = node_indices.get(&addr) {
                return idx;
            }

            let (name, raw_name, size, is_plt) = if let Some(sym) = symbol_map.resolve(addr) {
                (
                    sym.name.clone(),
                    sym.raw_name.clone(),
                    sym.end.saturating_sub(sym.start),
                    sym.is_plt,
                )
            } else {
                let name = format!("sub_0x{:x}", addr);
                (name.clone(), name, 0, false)
            };

            let node = FunctionNode {
                name,
                raw_name,
                address: addr,
                size,
                is_plt,
            };

            let idx = graph.add_node(node);
            node_indices.insert(addr, idx);
            idx
        };

        /* pre-populate all defined functions and PLT stubs in the DiGraph */
        for sym in symbol_map.iter() {
            let idx = graph.add_node(FunctionNode {
                name: sym.name.clone(),
                raw_name: sym.raw_name.clone(),
                address: sym.start,
                size: sym.end.saturating_sub(sym.start),
                is_plt: sym.is_plt,
            });
            node_indices.insert(sym.start, idx);
        }

        /* 4. disassemble each function's machine code bytes from .text and detect direct CALL instructions */
        for (i, &func_addr) in sorted_addrs.iter().enumerate() {
            /* skip symbols outside .text (e.g. .init or .fini) */
            if func_addr < text_addr || func_addr >= text_end {
                continue;
            }

            let (_demangled, _raw_name, explicit_size) = &raw_funcs[&func_addr];
            let func_size = if *explicit_size > 0 {
                *explicit_size
            } else if i + 1 < sorted_addrs.len() {
                sorted_addrs[i + 1].saturating_sub(func_addr)
            } else {
                text_end.saturating_sub(func_addr)
            };

            let offset_in_text = (func_addr - text_addr) as usize;
            if offset_in_text >= text_bytes.len() {
                continue;
            }

            let max_avail = text_bytes.len() - offset_in_text;
            let len = (func_size as usize).min(max_avail);
            let slice = &text_bytes[offset_in_text..offset_in_text + len];

            let caller_idx = get_or_insert_node(
                &mut graph,
                &mut node_indices,
                func_addr,
                &symbol_map,
            );

            /* decode instructions using iced-x86 64-bit decoder */
            let mut decoder = Decoder::with_ip(64, slice, func_addr, DecoderOptions::NONE);
            let mut instr = Instruction::default();

            while decoder.can_decode() {
                let ip = decoder.ip();
                decoder.decode_out(&mut instr);

                /* filter direct CALL instructions (near branch relative calls) */
                if instr.mnemonic() == Mnemonic::Call
                    && matches!(
                        instr.op0_kind(),
                        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                    )
                {
                    let target_addr = instr.near_branch_target();

                    /* resolve target address to function or PLT stub start address */
                    let callee_start_addr = if let Some(sym) = symbol_map.resolve(target_addr) {
                        sym.start
                    } else {
                        target_addr
                    };

                    let callee_idx = get_or_insert_node(
                        &mut graph,
                        &mut node_indices,
                        callee_start_addr,
                        &symbol_map,
                    );

                    /* add directed edge in DiGraph representing caller -> callee invocation */
                    graph.add_edge(caller_idx, callee_idx, CallEdge { call_site: ip });
                }
            }
        }

        /* 5. collect executable sections (.text, .plt, etc.) to allow runtime disassembly */
        let mut exec_sections = Vec::new();
        for sec in self.file.sections() {
            let name = sec.name().unwrap_or("");
            if sec.kind() == SectionKind::Text || name.contains("plt") || name == ".init" || name == ".fini" {
                if let Ok(data) = sec.data() {
                    if !data.is_empty() {
                        exec_sections.push(ExecutableSection {
                            name: name.to_string(),
                            address: sec.address(),
                            data: data.to_vec(),
                        });
                    }
                }
            }
        }

        Ok(CallGraph {
            graph,
            node_indices,
            symbol_map,
            exec_sections,
        })
    }

    /* resolves PLT trampoline stubs by correlating dynamic relocations in .rela.plt and .rela.dyn with RIP-relative indirect jumps */
    fn resolve_plt_stubs(&self) -> Result<Vec<FunctionNode>> {
        let mut stubs = Vec::new();

        /* build map from dynamic symbol index to demangled name */
        let mut dynsym_names = HashMap::new();
        for sym in self.file.dynamic_symbols() {
            if let Ok(raw_name) = sym.name() {
                let demangled = rustc_demangle::demangle(raw_name).to_string();
                dynsym_names.insert(sym.index(), (demangled, raw_name.to_string()));
            }
        }

        /* build map from GOT virtual address to dynamic symbol name */
        let mut got_to_symbol: HashMap<u64, (String, String)> = HashMap::new();
        if let Some(relocs) = self.file.dynamic_relocations() {
            for (got_addr, reloc) in relocs {
                if let RelocationTarget::Symbol(idx) = reloc.target() {
                    if let Some((demangled, raw_name)) = dynsym_names.get(&idx) {
                        got_to_symbol.insert(got_addr, (demangled.clone(), raw_name.clone()));
                    }
                }
            }
        }

        /* inspect PLT sections (.plt, .plt.sec, .plt.got) to match jump targets with GOT relocations */
        for sec_name in [".plt", ".plt.sec", ".plt.got"] {
            if let Some(sec) = self.file.section_by_name(sec_name) {
                let Ok(data) = sec.data() else { continue };
                let base = sec.address();

                let mut decoder = Decoder::with_ip(64, data, base, DecoderOptions::NONE);
                let mut instr = Instruction::default();

                while decoder.can_decode() {
                    let ip = decoder.ip();
                    decoder.decode_out(&mut instr);

                    /* check for RIP-relative indirect jump, e.g. "jmp *GOT(%rip)" */
                    if instr.is_ip_rel_memory_operand() {
                        let got_target = instr.ip_rel_memory_address();
                        if let Some((sym_name, raw_name)) = got_to_symbol.get(&got_target) {
                            /* on x86_64 ELF, PLT trampoline entries are 16-byte aligned relative to section base */
                            let offset_in_sec = ip.saturating_sub(base);
                            let stub_start = base + (offset_in_sec / 16) * 16;

                            stubs.push(FunctionNode {
                                name: format!("{}@plt", sym_name),
                                raw_name: format!("{}@plt", raw_name),
                                address: stub_start,
                                size: 16,
                                is_plt: true,
                            });
                        }
                    }
                }
            }
        }

        /* deduplicate stubs by start address */
        stubs.sort_by_key(|s| s.address);
        stubs.dedup_by_key(|s| s.address);

        Ok(stubs)
    }
}

/* convenience helper to read an ELF file from disk and reconstruct its CallGraph */
pub fn build_call_graph<P: AsRef<Path>>(path: P) -> Result<CallGraph> {
    let path = path.as_ref();
    let data = std::fs::read(path)
        .with_context(|| format!("Failed to read ELF binary at '{}'", path.display()))?;
    let builder = ElfCallGraphBuilder::new(&data)?;
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_disambiguators() {
        assert_eq!(
            strip_disambiguators("elf_graph[37b3ed3d4b78e678]::main"),
            "elf_graph::main"
        );
        assert_eq!(
            strip_disambiguators("std[6c98fd8553dbae28]::rt::lang_start"),
            "std::rt::lang_start"
        );
        assert_eq!(strip_disambiguators("main"), "main");
    }

    #[test]
    fn test_symbol_map_resolution() {
        let mut map = SymbolMap::new();
        map.insert(SymbolRange {
            name: "func_a".to_string(),
            raw_name: "func_a".to_string(),
            start: 0x1000,
            end: 0x1050,
            is_plt: false,
        });
        map.insert(SymbolRange {
            name: "puts@plt".to_string(),
            raw_name: "puts@plt".to_string(),
            start: 0x1050,
            end: 0x1060,
            is_plt: true,
        });

        /* test exact start address match */
        let res = map.resolve(0x1000);
        assert!(res.is_some());
        assert_eq!(res.unwrap().name, "func_a");

        /* test interior address match within [start, end) */
        let res_mid = map.resolve(0x1020);
        assert!(res_mid.is_some());
        assert_eq!(res_mid.unwrap().name, "func_a");

        /* test PLT stub match */
        let res_plt = map.resolve(0x1050);
        assert!(res_plt.is_some());
        assert_eq!(res_plt.unwrap().name, "puts@plt");
        assert!(res_plt.unwrap().is_plt);

        /* test out of bounds lookup */
        assert!(map.resolve(0x0fff).is_none());
        assert!(map.resolve(0x1060).is_none());
    }
}
