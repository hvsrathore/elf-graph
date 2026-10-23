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

/// Represents an executable section stored for runtime disassembly.
#[derive(Debug, Clone)]
pub struct ExecutableSection {
    pub name: String,
    pub address: u64,
    pub data: Vec<u8>,
}

/// A disassembled instruction line with call analysis.
#[derive(Debug, Clone)]
pub struct DisassembledLine {
    pub ip: u64,
    pub bytes: Vec<u8>,
    pub instruction_text: String,
    pub is_call: bool,
    pub call_target: Option<u64>,
    pub target_symbol: Option<String>,
}

/// Represents a function or call target node in the call graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionNode {
    /// Demangled or friendly symbol name.
    pub name: String,
    /// Raw mangled symbol name (if different).
    pub raw_name: String,
    /// Virtual start address in memory.
    pub address: u64,
    /// Size in bytes of the function (if known).
    pub size: u64,
    /// Whether this node represents a PLT trampoline stub.
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

/// Information associated with a directed call edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEdge {
    /// Virtual address of the direct CALL instruction.
    pub call_site: u64,
}

impl fmt::Display for CallEdge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "call site: 0x{:x}", self.call_site)
    }
}

/// Address range entry for fast symbol resolution.
#[derive(Debug, Clone)]
pub struct SymbolRange {
    pub name: String,
    pub raw_name: String,
    pub start: u64,
    pub end: u64,
    pub is_plt: bool,
}

/// A lookup map from virtual address ranges to symbol names.
#[derive(Debug, Default, Clone)]
pub struct SymbolMap {
    /// Map from start address to SymbolRange (ordered by start address).
    ranges: BTreeMap<u64, SymbolRange>,
}

impl SymbolMap {
    pub fn new() -> Self {
        Self {
            ranges: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, range: SymbolRange) {
        self.ranges.insert(range.start, range);
    }

    /// Resolve an address to a symbol name.
    /// Matches exact start address first, then checks if the address falls within [start, end).
    pub fn resolve(&self, addr: u64) -> Option<&SymbolRange> {
        // Check if there is a function starting at or before addr
        if let Some((&start, range)) = self.ranges.range(..=addr).next_back() {
            if addr == start || addr < range.end {
                return Some(range);
            }
        }
        None
    }

    pub fn iter(&self) -> impl Iterator<Item = &SymbolRange> {
        self.ranges.values()
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

/// Strips compiler disambiguators like `[c0acaeba6ab4c2e0]` from demangled symbol names.
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

/// The extracted Call Graph backed by `petgraph::graph::DiGraph`.
pub struct CallGraph {
    pub graph: DiGraph<FunctionNode, CallEdge>,
    pub node_indices: HashMap<u64, NodeIndex>,
    pub symbol_map: SymbolMap,
    pub exec_sections: Vec<ExecutableSection>,
}

impl CallGraph {
    /// Retrieve function byte slice from stored executable sections.
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

    /// Disassemble a function's instructions using iced-x86.
    pub fn disassemble_function(&self, addr: u64, size: u64) -> Vec<DisassembledLine> {
        let Some(bytes) = self.get_function_bytes(addr, size) else {
            return Vec::new();
        };

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

    /// Retrieve all node indices with a matching name.
    /// Supports exact matching, normalized demangled matching (without crate disambiguators),
    /// suffix matching (e.g. `main` matching `crate::main`), and substring fallback.
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

        // If searching for "main", include both C `main` and Rust `*::main`
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

    /// Get the outgoing adjacency list (direct callees) for a node index.
    pub fn outgoing_calls(&self, node_idx: NodeIndex) -> Vec<(&FunctionNode, &CallEdge)> {
        let mut callees = Vec::new();
        for edge_ref in self.graph.edges_directed(node_idx, Direction::Outgoing) {
            let callee_node = &self.graph[edge_ref.target()];
            let edge = edge_ref.weight();
            callees.push((callee_node, edge));
        }
        // Sort by call site address for deterministic and readable output
        callees.sort_by_key(|(_, edge)| edge.call_site);
        callees
    }

    /// Format the adjacency list for a given node index.
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

    /// Export the graph to Graphviz DOT format.
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

/// Analyzes an x86_64 ELF binary and builds a CallGraph.
pub struct ElfCallGraphBuilder<'a> {
    file: File<'a>,
}

impl<'a> ElfCallGraphBuilder<'a> {
    /// Load and validate an x86_64 ELF binary from byte slice.
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

    /// Build the full CallGraph.
    pub fn build(self) -> Result<CallGraph> {
        let mut symbol_map = SymbolMap::new();

        // 1. Resolve dynamic symbols and GOT relocations to locate PLT stubs
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

        // 2. Parse .symtab and .dynsym tables for STT_FUNC symbols
        let text_section = self
            .file
            .section_by_name(".text")
            .context("Binary does not contain a .text section")?;
        let text_addr = text_section.address();
        let text_size = text_section.size();
        let text_end = text_addr + text_size;
        let text_bytes = text_section.data().context("Failed to read .text section data")?;

        // Collect function symbols
        let mut raw_funcs: BTreeMap<u64, (String, String, u64)> = BTreeMap::new();

        // Helper to process symbols
        let mut process_symbol = |sym: &object::read::Symbol| {
            if sym.kind() == SymbolKind::Text && !sym.is_undefined() {
                let addr = sym.address();
                if addr != 0 {
                    let raw_name = sym.name().unwrap_or("").to_string();
                    let demangled = rustc_demangle::demangle(&raw_name).to_string();
                    let size = sym.size();

                    // Insert or update if size is more specific
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

        // Parse .symtab (file.symbols())
        for sym in self.file.symbols() {
            process_symbol(&sym);
        }

        // Parse .dynsym (file.dynamic_symbols())
        for sym in self.file.dynamic_symbols() {
            process_symbol(&sym);
        }

        // Determine effective function ranges
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
                16 // reasonable minimum fallback
            };

            symbol_map.insert(SymbolRange {
                name: demangled.clone(),
                raw_name: raw_name.clone(),
                start: addr,
                end: addr + effective_size,
                is_plt: false,
            });
        }

        // 3. Build petgraph::DiGraph
        let mut graph = DiGraph::<FunctionNode, CallEdge>::new();
        let mut node_indices = HashMap::<u64, NodeIndex>::new();

        // Helper to get or insert a node in the graph
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

        // Pre-populate defined functions in the graph
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

        // 4. Disassemble each function's bytes from .text and detect direct CALLs
        for (i, &func_addr) in sorted_addrs.iter().enumerate() {
            // Only disassemble functions residing in .text
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

            // Disassemble instructions
            let mut decoder = Decoder::with_ip(64, slice, func_addr, DecoderOptions::NONE);
            let mut instr = Instruction::default();

            while decoder.can_decode() {
                let ip = decoder.ip();
                decoder.decode_out(&mut instr);

                // Detect direct CALL instructions
                if instr.mnemonic() == Mnemonic::Call
                    && matches!(
                        instr.op0_kind(),
                        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                    )
                {
                    let target_addr = instr.near_branch_target();

                    // Find matching callee node:
                    // Check if target is a known function or PLT stub start address
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

                    graph.add_edge(caller_idx, callee_idx, CallEdge { call_site: ip });
                }
            }
        }

        // 5. Collect executable sections for runtime disassembly
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

    /// Resolves PLT stubs by correlating dynamic relocations (`.rela.plt` and `.rela.dyn`)
    /// with indirect jump instructions inside `.plt`, `.plt.sec`, and `.plt.got` sections.
    fn resolve_plt_stubs(&self) -> Result<Vec<FunctionNode>> {
        let mut stubs = Vec::new();

        // 1. Build map of dynamic symbol index -> demangled name
        let mut dynsym_names = HashMap::new();
        for sym in self.file.dynamic_symbols() {
            if let Ok(raw_name) = sym.name() {
                let demangled = rustc_demangle::demangle(raw_name).to_string();
                dynsym_names.insert(sym.index(), (demangled, raw_name.to_string()));
            }
        }

        // 2. Build map of GOT address -> dynamic symbol
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

        // 3. Inspect PLT sections: .plt, .plt.sec, .plt.got
        for sec_name in [".plt", ".plt.sec", ".plt.got"] {
            if let Some(sec) = self.file.section_by_name(sec_name) {
                let Ok(data) = sec.data() else { continue };
                let base = sec.address();

                // Decode using iced-x86
                let mut decoder = Decoder::with_ip(64, data, base, DecoderOptions::NONE);
                let mut instr = Instruction::default();

                while decoder.can_decode() {
                    let ip = decoder.ip();
                    decoder.decode_out(&mut instr);

                    // Check for RIP-relative indirect jump (e.g. `jmp *GOT(%rip)`)
                    if instr.is_ip_rel_memory_operand() {
                        let got_target = instr.ip_rel_memory_address();
                        if let Some((sym_name, raw_name)) = got_to_symbol.get(&got_target) {
                            // On x86_64 ELF:
                            // PLT entries are aligned to 16 bytes relative to base.
                            // Even with CET `endbr64` at offset 0 and `jmp` at offset 4,
                            // the stub entry point is the 16-byte boundary.
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

        // Deduplicate stubs by address
        stubs.sort_by_key(|s| s.address);
        stubs.dedup_by_key(|s| s.address);

        Ok(stubs)
    }
}

/// Convenience function to build a CallGraph from an ELF binary path.
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

        // Exact match
        let res = map.resolve(0x1000);
        assert!(res.is_some());
        assert_eq!(res.unwrap().name, "func_a");

        // Interior offset
        let res_mid = map.resolve(0x1020);
        assert!(res_mid.is_some());
        assert_eq!(res_mid.unwrap().name, "func_a");

        // PLT stub match
        let res_plt = map.resolve(0x1050);
        assert!(res_plt.is_some());
        assert_eq!(res_plt.unwrap().name, "puts@plt");
        assert!(res_plt.unwrap().is_plt);

        // Outside range
        assert!(map.resolve(0x0fff).is_none());
        assert!(map.resolve(0x1060).is_none());
    }
}
