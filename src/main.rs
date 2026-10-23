use std::path::PathBuf;
use std::process;

use anyhow::Result;
use clap::Parser;
use elf_graph::build_call_graph;

#[derive(Parser, Debug)]
#[command(
    name = "elf-graph",
    author,
    version,
    about = "Disassembles x86_64 ELF binaries, reconstructs call graphs with petgraph, and resolves PLT stubs"
)]
struct Args {
    /// Path to the x86_64 ELF binary to analyze
    #[arg(value_name = "BINARY")]
    binary: PathBuf,

    /// Function name to inspect and print the adjacency list for (default: "main")
    #[arg(short, long, default_value = "main")]
    function: String,

    /// Print adjacency lists for all functions in the binary
    #[arg(short, long)]
    all: bool,

    /// Export the reconstructed call graph to Graphviz DOT format
    #[arg(long)]
    dot: bool,

    /// Print summary statistics of the reconstructed call graph
    #[arg(short, long)]
    stats: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if !args.binary.exists() {
        eprintln!("Error: Binary file not found: {}", args.binary.display());
        process::exit(1);
    }

    if !args.dot {
        eprintln!("Analyzing ELF binary: {}", args.binary.display());
    }

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

    if args.stats || (!args.dot && !args.all) {
        println!(
            "Successfully built call graph: {} functions/targets (including {} PLT stubs), {} direct call edges",
            node_count, plt_count, edge_count
        );
        println!();
    }

    if args.dot {
        println!("{}", call_graph.to_dot());
        return Ok(());
    }

    if args.all {
        println!("=== Adjacency Lists for All Functions ===");
        for node_idx in call_graph.graph.node_indices() {
            let node = &call_graph.graph[node_idx];
            // Only show defined functions by default unless PLT stubs have outgoing edges
            if !node.is_plt {
                println!("{}", call_graph.format_adjacency_list(node_idx));
            }
        }
        return Ok(());
    }

    // Default: print adjacency list of requested function (default: "main")
    let target_func = &args.function;
    let matching_nodes = call_graph.find_nodes_by_name(target_func);

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
