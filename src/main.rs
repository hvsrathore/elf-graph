use std::io::IsTerminal;
use std::path::PathBuf;
use std::process;

use anyhow::Result;
use clap::Parser;
use elf_graph::build_call_graph;
use elf_graph::tui::run_tui;

#[derive(Parser, Debug)]
#[command(
    name = "elf-graph",
    author,
    version,
    about = "Disassembles x86_64 ELF binaries, reconstructs call graphs with petgraph, and explores with an interactive Ratatui TUI"
)]
struct Args {
    /// Path to the x86_64 ELF binary to analyze
    #[arg(value_name = "BINARY")]
    binary: PathBuf,

    /// Function name to inspect or start TUI exploration from (default: "main")
    #[arg(short, long, default_value = "main")]
    function: String,

    /// Print text adjacency lists for all functions in the binary
    #[arg(short, long)]
    all: bool,

    /// Export the reconstructed call graph to Graphviz DOT format
    #[arg(long)]
    dot: bool,

    /// Print text adjacency list to stdout (non-interactive mode)
    #[arg(long)]
    cli: bool,

    /// Launch interactive 3-pane Ratatui TUI
    #[arg(short, long)]
    tui: bool,

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

    let should_launch_tui =
        args.tui || (!args.dot && !args.all && !args.cli && std::io::stdout().is_terminal());

    if !args.dot && !should_launch_tui {
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

    if args.dot {
        println!("{}", call_graph.to_dot());
        return Ok(());
    }

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

    // Locate requested function (default: "main")
    let target_func = &args.function;
    let mut matching_nodes = call_graph.find_nodes_by_name(target_func);

    // Prioritize functions with more outgoing calls (e.g. user `crate::main` over runtime stub)
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
        // Fallback to non-PLT function with the most outgoing calls
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

    // Launch interactive TUI
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

    // CLI mode: print statistics and adjacency list verification
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
