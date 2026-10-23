use std::io::IsTerminal;
use std::path::PathBuf;
use std::process;

use anyhow::Result;
use clap::Parser;
use elf_graph::build_call_graph;
use elf_graph::tui::run_tui;

/* command line arguments parsed via clap */
#[derive(Parser, Debug)]
#[command(
    name = "elf-graph",
    author,
    version,
    about = "Disassembles x86_64 ELF binaries, reconstructs call graphs with petgraph, and explores with an interactive Ratatui TUI"
)]
struct Args {
    /* path to the target x86_64 ELF binary to disassemble and analyze */
    #[arg(value_name = "BINARY", help = "path to the x86_64 ELF binary to analyze")]
    binary: PathBuf,

    /* symbol name to inspect or use as initial root in the TUI (defaults to "main") */
    #[arg(short, long, default_value = "main", help = "function name to inspect or start TUI exploration from")]
    function: String,

    /* dump text adjacency lists for all functions in the binary to stdout */
    #[arg(short, long, help = "print text adjacency lists for all functions in the binary")]
    all: bool,

    /* export the full graph to standard Graphviz DOT format for graph visualization tools */
    #[arg(long, help = "export the reconstructed call graph to Graphviz DOT format")]
    dot: bool,

    /* force non-interactive CLI mode even when running in a terminal */
    #[arg(long, help = "print text adjacency list to stdout (non-interactive mode)")]
    cli: bool,

    /* launch interactive Ratatui TUI explorer */
    #[arg(short, long, help = "launch interactive 3-pane Ratatui TUI")]
    tui: bool,

    /* print summary statistics such as total functions, PLT stubs, and call edges */
    #[arg(short, long, help = "print summary statistics of the reconstructed call graph")]
    stats: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    /* verify that the provided binary path exists on the filesystem */
    if !args.binary.exists() {
        eprintln!("Error: Binary file not found: {}", args.binary.display());
        process::exit(1);
    }

    /* launch TUI if explicitly requested or if running interactively in a terminal without dump flags */
    let should_launch_tui =
        args.tui || (!args.dot && !args.all && !args.cli && std::io::stdout().is_terminal());

    if !args.dot && !should_launch_tui {
        eprintln!("Analyzing ELF binary: {}", args.binary.display());
    }

    /* parse the ELF binary, resolve symbols/PLT, disassemble .text, and construct the petgraph DiGraph */
    let call_graph = match build_call_graph(&args.binary) {
        Ok(cg) => cg,
        Err(err) => {
            eprintln!("Failed to analyze ELF binary: {:#}", err);
            process::exit(1);
        }
    };

    let node_count = call_graph.graph.node_count();
    let edge_count = call_graph.graph.edge_count();
    let plt_count = call_graph
        .graph
        .node_weights()
        .filter(|n| n.is_plt)
        .count();

    /* handle DOT graph export request */
    if args.dot {
        println!("{}", call_graph.to_dot());
        return Ok(());
    }

    /* handle full adjacency list print request */
    if args.all {
        println!("=== Adjacency Lists for All Functions ===");
        for node_idx in call_graph.graph.node_indices() {
            let node = &call_graph.graph[node_idx];
            if !node.is_plt {
                println!("{}", call_graph.format_adjacency_list(node_idx));
            }
        }
        return Ok(());
    }

    /* locate requested function symbol (defaults to "main") */
    let target_func = &args.function;
    let mut matching_nodes = call_graph.find_nodes_by_name(target_func);

    /* prioritize functions with more outgoing direct calls so user code (e.g. crate::main) precedes runtime stubs */
    matching_nodes.sort_by(|&a, &b| {
        let out_b = call_graph
            .graph
            .edges_directed(b, petgraph::Direction::Outgoing)
            .count();
        let out_a = call_graph
            .graph
            .edges_directed(a, petgraph::Direction::Outgoing)
            .count();
        out_b.cmp(&out_a)
    });

    let start_node = if !matching_nodes.is_empty() {
        matching_nodes[0]
    } else {
        /* fallback to the non-PLT function with the highest out-degree (most outgoing calls) */
        call_graph
            .graph
            .node_indices()
            .filter(|&idx| !call_graph.graph[idx].is_plt)
            .max_by_key(|&idx| {
                call_graph
                    .graph
                    .edges_directed(idx, petgraph::Direction::Outgoing)
                    .count()
            })
            .unwrap_or_else(|| call_graph.graph.node_indices().next().unwrap())
    };

    /* launch interactive Ratatui TUI */
    if should_launch_tui {
        let binary_name = args
            .binary
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("binary")
            .to_string();

        run_tui(&call_graph, start_node, binary_name)?;
        return Ok(());
    }

    /* CLI non-interactive mode: output call graph summary and adjacency list of matched symbols */
    if args.stats || !args.all {
        println!(
            "Successfully built call graph: {} functions/targets (including {} PLT stubs), {} direct call edges",
            node_count, plt_count, edge_count
        );
        println!();
    }

    if matching_nodes.is_empty() {
        eprintln!(
            "Function '{}' not found in symbol table or dynamic symbols.",
            target_func
        );
        eprintln!();
        eprintln!("Available functions include:");
        let mut sample_names: Vec<_> = call_graph
            .graph
            .node_weights()
            .filter(|n| !n.is_plt)
            .map(|n| n.name.as_str())
            .collect();
        sample_names.sort();
        for name in sample_names.iter().take(20) {
            eprintln!("  - {}", name);
        }
        if sample_names.len() > 20 {
            eprintln!("  ... and {} more", sample_names.len() - 20);
        }
        process::exit(1);
    }

    println!("=== Adjacency List Verification ===");
    for &node_idx in &matching_nodes {
        println!("{}", call_graph.format_adjacency_list(node_idx));
    }

    Ok(())
}
