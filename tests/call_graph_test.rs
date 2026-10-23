use std::fs;
use std::process::Command;
use elf_graph::build_call_graph;

#[test]
fn test_call_graph_c_binary_with_plt() {
    let temp_dir = std::env::temp_dir();
    let src_path = temp_dir.join("test_callgraph_src.c");
    let bin_path = temp_dir.join("test_callgraph_bin");

    let c_code = r#"
#include <stdio.h>

void func_d() {
    puts("leaf function");
}

void func_c() {
    func_d();
}

void func_b() {
    func_c();
}

void func_a() {
    func_b();
}

int main() {
    func_a();
    puts("done");
    return 0;
}
"#;

    fs::write(&src_path, c_code).expect("Failed to write test C file");

    let status = Command::new("gcc")
        .args([
            "-O0",
            "-no-pie",
            "-fno-omit-frame-pointer",
            src_path.to_str().unwrap(),
            "-o",
            bin_path.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to run gcc compiler");

    assert!(status.success(), "gcc compilation failed");

    let call_graph = build_call_graph(&bin_path).expect("Failed to build call graph");

    // Verify main node exists
    let main_nodes = call_graph.find_nodes_by_name("main");
    assert!(!main_nodes.is_empty(), "main function must be found");

    let main_idx = main_nodes[0];
    let callees = call_graph.outgoing_calls(main_idx);

    // Main should call func_a and puts@plt
    let callee_names: Vec<&str> = callees.iter().map(|(n, _)| n.name.as_str()).collect();
    println!("Main callees: {:?}", callee_names);

    assert!(
        callee_names.iter().any(|name| *name == "func_a"),
        "main must call func_a"
    );
    assert!(
        callee_names.iter().any(|name| name.contains("puts")),
        "main must call puts (or puts@plt)"
    );

    // Verify func_a calls func_b
    let func_a_nodes = call_graph.find_nodes_by_name("func_a");
    assert!(!func_a_nodes.is_empty());
    let a_callees = call_graph.outgoing_calls(func_a_nodes[0]);
    let a_callee_names: Vec<&str> = a_callees.iter().map(|(n, _)| n.name.as_str()).collect();
    assert!(a_callee_names.contains(&"func_b"));

    // Verify func_b calls func_c
    let func_b_nodes = call_graph.find_nodes_by_name("func_b");
    assert!(!func_b_nodes.is_empty());
    let b_callees = call_graph.outgoing_calls(func_b_nodes[0]);
    let b_callee_names: Vec<&str> = b_callees.iter().map(|(n, _)| n.name.as_str()).collect();
    assert!(b_callee_names.contains(&"func_c"));

    // Verify func_c calls func_d
    let func_c_nodes = call_graph.find_nodes_by_name("func_c");
    assert!(!func_c_nodes.is_empty());
    let c_callees = call_graph.outgoing_calls(func_c_nodes[0]);
    let c_callee_names: Vec<&str> = c_callees.iter().map(|(n, _)| n.name.as_str()).collect();
    assert!(c_callee_names.contains(&"func_d"));

    // Clean up
    let _ = fs::remove_file(&src_path);
    let _ = fs::remove_file(&bin_path);
}

#[test]
fn test_invalid_elf_rejection() {
    let temp_dir = std::env::temp_dir();
    let dummy_path = temp_dir.join("not_an_elf.bin");
    fs::write(&dummy_path, b"This is plain text, not ELF").unwrap();

    let result = build_call_graph(&dummy_path);
    assert!(result.is_err());

    let _ = fs::remove_file(&dummy_path);
}
