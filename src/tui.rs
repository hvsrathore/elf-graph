use std::collections::HashSet;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use ratatui::layout::{Constraint, Direction as LayoutDirection, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph, Wrap};
use ratatui::DefaultTerminal;

use crate::{CallEdge, CallGraph, FunctionNode};

/// Represents a node in the callee tree (up to depth 3).
#[derive(Debug, Clone)]
pub struct TreeNode {
    pub id: usize,
    pub node_idx: NodeIndex,
    pub depth: usize,
    pub call_site: Option<u64>,
    pub children: Vec<TreeNode>,
    pub is_recursive: bool,
}

/// A visible row in the flattened collapsible tree view.
#[derive(Debug, Clone)]
pub struct VisibleRow {
    pub tree_id: usize,
    pub node_idx: NodeIndex,
    pub depth: usize,
    pub call_site: Option<u64>,
    pub is_expanded: bool,
    pub has_children: bool,
    pub is_recursive: bool,
}

/// TUI Application state.
pub struct AppState {
    pub binary_name: String,
    pub current_node: NodeIndex,
    pub history: Vec<NodeIndex>,
    pub selected_index: usize,
    pub scroll_offset: usize,
    pub caller_scroll_offset: usize,
    pub collapsed_ids: HashSet<usize>,
    pub tree_root: TreeNode,
    pub visible_rows: Vec<VisibleRow>,
}

impl AppState {
    pub fn new(
        graph: &DiGraph<FunctionNode, CallEdge>,
        initial_node: NodeIndex,
        binary_name: String,
    ) -> Self {
        let mut app = Self {
            binary_name,
            current_node: initial_node,
            history: Vec::new(),
            selected_index: 0,
            scroll_offset: 0,
            caller_scroll_offset: 0,
            collapsed_ids: HashSet::new(),
            tree_root: TreeNode {
                id: 0,
                node_idx: initial_node,
                depth: 0,
                call_site: None,
                children: Vec::new(),
                is_recursive: false,
            },
            visible_rows: Vec::new(),
        };

        app.rebuild_tree(graph);
        app
    }

    /// Rebuilds the callee tree for `current_node` up to depth 3 and re-flattens visible rows.
    pub fn rebuild_tree(&mut self, graph: &DiGraph<FunctionNode, CallEdge>) {
        let mut next_id = 0;
        let mut ancestors = Vec::new();
        self.tree_root = Self::build_callee_tree(
            graph,
            self.current_node,
            0,
            3,
            None,
            &mut ancestors,
            &mut next_id,
        );

        // Keep collapsed_ids or reset
        self.refresh_visible_rows();

        // Default cursor to the first callee if available, otherwise root
        if self.visible_rows.len() > 1 {
            self.selected_index = 1;
        } else {
            self.selected_index = 0;
        }
        self.scroll_offset = 0;
        self.caller_scroll_offset = 0;
    }

    /// Recursively constructs the callee tree up to `max_depth`.
    fn build_callee_tree(
        graph: &DiGraph<FunctionNode, CallEdge>,
        current_idx: NodeIndex,
        depth: usize,
        max_depth: usize,
        call_site: Option<u64>,
        ancestors: &mut Vec<NodeIndex>,
        next_id: &mut usize,
    ) -> TreeNode {
        let id = *next_id;
        *next_id += 1;

        let is_recursive = ancestors.contains(&current_idx);
        let mut children = Vec::new();

        if depth < max_depth && !is_recursive {
            ancestors.push(current_idx);

            let mut outgoing: Vec<_> = graph
                .edges_directed(current_idx, Direction::Outgoing)
                .map(|edge| (edge.target(), edge.weight().call_site))
                .collect();

            // Sort by call site address for deterministic layout
            outgoing.sort_by_key(|(_, site)| *site);

            for (target_idx, site) in outgoing {
                children.push(Self::build_callee_tree(
                    graph,
                    target_idx,
                    depth + 1,
                    max_depth,
                    Some(site),
                    ancestors,
                    next_id,
                ));
            }

            ancestors.pop();
        }

        TreeNode {
            id,
            node_idx: current_idx,
            depth,
            call_site,
            children,
            is_recursive,
        }
    }

    /// Flattens the tree into currently visible rows based on `collapsed_ids`.
    pub fn refresh_visible_rows(&mut self) {
        self.visible_rows.clear();
        Self::flatten_tree(&self.tree_root, &self.collapsed_ids, &mut self.visible_rows);

        if self.selected_index >= self.visible_rows.len() {
            self.selected_index = self.visible_rows.len().saturating_sub(1);
        }
    }

    fn flatten_tree(
        node: &TreeNode,
        collapsed: &HashSet<usize>,
        out: &mut Vec<VisibleRow>,
    ) {
        let has_children = !node.children.is_empty();
        let is_expanded = has_children && !collapsed.contains(&node.id);

        out.push(VisibleRow {
            tree_id: node.id,
            node_idx: node.node_idx,
            depth: node.depth,
            call_site: node.call_site,
            is_expanded,
            has_children,
            is_recursive: node.is_recursive,
        });

        if is_expanded {
            for child in &node.children {
                Self::flatten_tree(child, collapsed, out);
            }
        }
    }

    /// Navigate selection down (`j`).
    pub fn move_down(&mut self) {
        if self.selected_index + 1 < self.visible_rows.len() {
            self.selected_index += 1;
        }
    }

    /// Navigate selection up (`k`).
    pub fn move_up(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    /// Toggle expansion of the selected tree item.
    pub fn toggle_expand(&mut self) {
        if let Some(row) = self.visible_rows.get(self.selected_index) {
            if row.has_children {
                if self.collapsed_ids.contains(&row.tree_id) {
                    self.collapsed_ids.remove(&row.tree_id);
                } else {
                    self.collapsed_ids.insert(row.tree_id);
                }
                self.refresh_visible_rows();
            }
        }
    }

    /// Jump into the selected function, pushing the current node onto the history stack (`Enter`).
    pub fn jump_into_selected(&mut self, graph: &DiGraph<FunctionNode, CallEdge>) {
        if let Some(row) = self.visible_rows.get(self.selected_index) {
            let target_node = row.node_idx;
            if target_node != self.current_node {
                self.history.push(self.current_node);
                self.current_node = target_node;
                self.rebuild_tree(graph);
            }
        }
    }

    /// Pop back to the previous function from history (`Backspace`).
    pub fn pop_history(&mut self, graph: &DiGraph<FunctionNode, CallEdge>) {
        if let Some(prev) = self.history.pop() {
            self.current_node = prev;
            self.rebuild_tree(graph);
        }
    }
}

/// Runs the Ratatui + Crossterm interactive TUI.
pub fn run_tui(call_graph: &CallGraph, start_node: NodeIndex, binary_name: String) -> Result<()> {
    let mut terminal = ratatui::init();
    let mut app = AppState::new(&call_graph.graph, start_node, binary_name);

    let res = run_app(&mut terminal, call_graph, &mut app);
    ratatui::restore();

    res
}

fn run_app(
    terminal: &mut DefaultTerminal,
    call_graph: &CallGraph,
    app: &mut AppState,
) -> Result<()> {
    loop {
        terminal.draw(|frame| {
            render_ui(frame, call_graph, app);
        })?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            break;
                        }
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            break;
                        }
                        KeyCode::Char('j') | KeyCode::Down => {
                            app.move_down();
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            app.move_up();
                        }
                        KeyCode::Enter => {
                            app.jump_into_selected(&call_graph.graph);
                        }
                        KeyCode::Backspace => {
                            app.pop_history(&call_graph.graph);
                        }
                        KeyCode::Char(' ') | KeyCode::Tab | KeyCode::Right | KeyCode::Left => {
                            app.toggle_expand();
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    Ok(())
}

fn render_ui(frame: &mut ratatui::Frame, call_graph: &CallGraph, app: &mut AppState) {
    let size = frame.area();

    // Vertical layout: Header (3 lines), Main 3-Pane area (remaining), Footer (3 lines)
    let chunks = Layout::default()
        .direction(LayoutDirection::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(size);

    let header_area = chunks[0];
    let main_area = chunks[1];
    let footer_area = chunks[2];

    // Horizontal split for the 3 Panes: Left (25%), Center (45%), Right (30%)
    let pane_chunks = Layout::default()
        .direction(LayoutDirection::Horizontal)
        .constraints([
            Constraint::Percentage(26),
            Constraint::Percentage(46),
            Constraint::Percentage(28),
        ])
        .split(main_area);

    let left_area = pane_chunks[0];
    let center_area = pane_chunks[1];
    let right_area = pane_chunks[2];

    // 1. Render Header
    render_header(frame, header_area, call_graph, app);

    // 2. Render Left Pane (Callers - Direction::Incoming)
    render_left_pane(frame, left_area, call_graph, app);

    // 3. Render Center Pane (Callee Tree - Direction::Outgoing up to Depth 3)
    render_center_pane(frame, center_area, call_graph, app);

    // 4. Render Right Pane (Function Metadata)
    render_right_pane(frame, right_area, call_graph, app);

    // 5. Render Footer
    render_footer(frame, footer_area, app);
}

fn render_header(
    frame: &mut ratatui::Frame,
    area: Rect,
    call_graph: &CallGraph,
    app: &AppState,
) {
    let current_func = &call_graph.graph[app.current_node];

    let mut path_spans = Vec::new();
    path_spans.push(Span::styled(" Root: ", Style::default().fg(Color::DarkGray)));

    for &hist_idx in &app.history {
        let node = &call_graph.graph[hist_idx];
        path_spans.push(Span::styled(
            &node.name,
            Style::default().fg(Color::LightCyan),
        ));
        path_spans.push(Span::styled(" > ", Style::default().fg(Color::DarkGray)));
    }

    path_spans.push(Span::styled(
        &current_func.name,
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    ));

    let header_line = Line::from(path_spans);

    let title_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Span::styled(
            format!(" ELF Call Graph Explorer - {} ", app.binary_name),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));

    let header_para = Paragraph::new(vec![header_line]).block(title_block);
    frame.render_widget(header_para, area);
}

fn render_left_pane(
    frame: &mut ratatui::Frame,
    area: Rect,
    call_graph: &CallGraph,
    app: &AppState,
) {
    // Incoming callers of current_node
    let mut callers: Vec<_> = call_graph
        .graph
        .edges_directed(app.current_node, Direction::Incoming)
        .map(|edge| {
            let caller = &call_graph.graph[edge.source()];
            let site = edge.weight().call_site;
            (caller, site)
        })
        .collect();

    callers.sort_by_key(|(_, site)| *site);

    let title = format!(" Callers [Incoming: {}] ", callers.len());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Blue))
        .title(Span::styled(
            title,
            Style::default()
                .fg(Color::LightBlue)
                .add_modifier(Modifier::BOLD),
        ));

    let mut lines = Vec::new();

    if callers.is_empty() {
        lines.push(Line::from(Span::styled(
            " (No incoming callers)",
            Style::default().fg(Color::DarkGray).italic(),
        )));
    } else {
        for (caller, site) in callers {
            let name_style = if caller.is_plt {
                Style::default().fg(Color::Magenta)
            } else {
                Style::default().fg(Color::Cyan)
            };

            lines.push(Line::from(vec![
                Span::styled(" ← ", Style::default().fg(Color::Blue)),
                Span::styled(&caller.name, name_style.add_modifier(Modifier::BOLD)),
            ]));
            lines.push(Line::from(vec![
                Span::styled(
                    format!("    at 0x{:x} [call: 0x{:x}]", caller.address, site),
                    Style::default().fg(Color::DarkGray),
                ),
            ]));
        }
    }

    let para = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

fn render_center_pane(
    frame: &mut ratatui::Frame,
    area: Rect,
    call_graph: &CallGraph,
    app: &mut AppState,
) {
    let title = format!(
        " Callee Tree (Outgoing ≤ Depth 3) [{}/{}] ",
        if app.visible_rows.is_empty() {
            0
        } else {
            app.selected_index + 1
        },
        app.visible_rows.len()
    );

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Green))
        .title(Span::styled(
            title,
            Style::default()
                .fg(Color::LightGreen)
                .add_modifier(Modifier::BOLD),
        ));

    let inner_height = area.height.saturating_sub(2) as usize;

    // Adjust scroll offset to keep selected_index visible
    if app.selected_index < app.scroll_offset {
        app.scroll_offset = app.selected_index;
    } else if app.selected_index >= app.scroll_offset + inner_height {
        app.scroll_offset = app.selected_index + 1 - inner_height;
    }

    let mut lines = Vec::new();

    for (idx, row) in app
        .visible_rows
        .iter()
        .enumerate()
        .skip(app.scroll_offset)
        .take(inner_height)
    {
        let is_selected = idx == app.selected_index;
        let node = &call_graph.graph[row.node_idx];

        let mut spans = Vec::new();

        // Cursor prefix
        if is_selected {
            spans.push(Span::styled(
                ">> ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::raw("   "));
        }

        // Tree indentation
        for _ in 0..row.depth {
            spans.push(Span::styled("│  ", Style::default().fg(Color::DarkGray)));
        }

        // Expand / collapse branch indicator
        if row.has_children {
            let symbol = if row.is_expanded { "▼ " } else { "▶ " };
            spans.push(Span::styled(
                symbol,
                Style::default().fg(Color::LightYellow),
            ));
        } else if row.depth > 0 {
            spans.push(Span::styled("• ", Style::default().fg(Color::DarkGray)));
        } else {
            spans.push(Span::styled("◆ ", Style::default().fg(Color::Green)));
        }

        // Node name with color coding
        let mut name_style = if row.is_recursive {
            Style::default().fg(Color::Red)
        } else if node.is_plt {
            Style::default().fg(Color::Magenta)
        } else if row.depth == 0 {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };

        if is_selected {
            name_style = name_style
                .bg(Color::Rgb(30, 45, 60))
                .add_modifier(Modifier::BOLD);
        }

        spans.push(Span::styled(&node.name, name_style));

        // Call site annotation
        if let Some(site) = row.call_site {
            spans.push(Span::styled(
                format!(" [0x{:x}]", site),
                Style::default().fg(Color::DarkGray),
            ));
        }

        if row.is_recursive {
            spans.push(Span::styled(
                " (recursive)",
                Style::default().fg(Color::Red).italic(),
            ));
        }

        lines.push(Line::from(spans));
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            " (No outgoing direct calls)",
            Style::default().fg(Color::DarkGray).italic(),
        )));
    }

    let para = Paragraph::new(lines).block(block);
    frame.render_widget(para, area);
}

fn render_right_pane(
    frame: &mut ratatui::Frame,
    area: Rect,
    call_graph: &CallGraph,
    app: &AppState,
) {
    // Target node for metadata: selected row in center tree (or current_node)
    let (target_node, target_idx, call_site) =
        if let Some(row) = app.visible_rows.get(app.selected_index) {
            (&call_graph.graph[row.node_idx], row.node_idx, row.call_site)
        } else {
            (&call_graph.graph[app.current_node], app.current_node, None)
        };

    let in_degree = call_graph
        .graph
        .edges_directed(target_idx, Direction::Incoming)
        .count();
    let out_degree = call_graph
        .graph
        .edges_directed(target_idx, Direction::Outgoing)
        .count();

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Magenta))
        .title(Span::styled(
            " Function Metadata ",
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD),
        ));

    let mut lines = Vec::new();

    // Section 1: Identity
    lines.push(Line::from(Span::styled(
        "IDENTIFIER",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
    )));
    lines.push(Line::from(vec![
        Span::styled("Name: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            &target_node.name,
            Style::default()
                .fg(if target_node.is_plt {
                    Color::Magenta
                } else {
                    Color::White
                })
                .add_modifier(Modifier::BOLD),
        ),
    ]));

    if target_node.raw_name != target_node.name {
        lines.push(Line::from(vec![
            Span::styled("Mangled: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&target_node.raw_name, Style::default().fg(Color::Gray)),
        ]));
    }

    lines.push(Line::from(vec![
        Span::styled("Kind: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            if target_node.is_plt {
                "PLT Stub Trampoline"
            } else {
                "Standard Function (.text)"
            },
            Style::default().fg(if target_node.is_plt {
                Color::Magenta
            } else {
                Color::Green
            }),
        ),
    ]));

    lines.push(Line::from(""));

    // Section 2: Layout & Geometry
    lines.push(Line::from(Span::styled(
        "VIRTUAL MEMORY",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
    )));
    lines.push(Line::from(vec![
        Span::styled("Address: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("0x{:08x}", target_node.address),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    ]));

    lines.push(Line::from(vec![
        Span::styled("Size:    ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{} bytes (0x{:x})", target_node.size, target_node.size),
            Style::default().fg(Color::Cyan),
        ),
    ]));

    if let Some(site) = call_site {
        lines.push(Line::from(vec![
            Span::styled("Callsite:", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("0x{:08x}", site),
                Style::default().fg(Color::LightYellow),
            ),
        ]));
    }

    lines.push(Line::from(""));

    // Section 3: Graph Topology
    lines.push(Line::from(Span::styled(
        "GRAPH TOPOLOGY",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
    )));
    lines.push(Line::from(vec![
        Span::styled("In-degree  (Callers): ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{}", in_degree),
            Style::default()
                .fg(Color::LightBlue)
                .add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Out-degree (Callees): ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{}", out_degree),
            Style::default()
                .fg(Color::LightGreen)
                .add_modifier(Modifier::BOLD),
        ),
    ]));

    lines.push(Line::from(""));

    // Section 4: History Trail
    lines.push(Line::from(Span::styled(
        "NAVIGATION",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
    )));
    lines.push(Line::from(vec![
        Span::styled("History Depth: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{} steps", app.history.len()),
            Style::default().fg(Color::White),
        ),
    ]));

    let para = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    frame.render_widget(para, area);
}

fn render_footer(frame: &mut ratatui::Frame, area: Rect, app: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray));

    let history_hint = if app.history.is_empty() {
        Span::styled("[Backspace] Back (empty)", Style::default().fg(Color::DarkGray))
    } else {
        Span::styled(
            format!("[Backspace] Pop to #{}", app.history.len()),
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        )
    };

    let help_spans = vec![
        Span::styled(" Controls: ", Style::default().fg(Color::Yellow).bold()),
        Span::styled("[j/k or ↓/↑] ", Style::default().fg(Color::White).bold()),
        Span::styled("Navigate  ", Style::default().fg(Color::DarkGray)),
        Span::styled("[Space] ", Style::default().fg(Color::White).bold()),
        Span::styled("Fold/Unfold  ", Style::default().fg(Color::DarkGray)),
        Span::styled("[Enter] ", Style::default().fg(Color::White).bold()),
        Span::styled("Jump Into  ", Style::default().fg(Color::DarkGray)),
        history_hint,
        Span::styled("  ", Style::default()),
        Span::styled("[q/Esc] ", Style::default().fg(Color::Red).bold()),
        Span::styled("Quit", Style::default().fg(Color::DarkGray)),
    ];

    let para = Paragraph::new(Line::from(help_spans)).block(block);
    frame.render_widget(para, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CallEdge, FunctionNode};
    use petgraph::graph::DiGraph;

    fn create_test_graph() -> (DiGraph<FunctionNode, CallEdge>, NodeIndex, NodeIndex, NodeIndex) {
        let mut g = DiGraph::new();
        let main = g.add_node(FunctionNode {
            name: "main".to_string(),
            raw_name: "main".to_string(),
            address: 0x1000,
            size: 30,
            is_plt: false,
        });
        let func_a = g.add_node(FunctionNode {
            name: "func_a".to_string(),
            raw_name: "func_a".to_string(),
            address: 0x2000,
            size: 20,
            is_plt: false,
        });
        let puts_plt = g.add_node(FunctionNode {
            name: "puts@plt".to_string(),
            raw_name: "puts@plt".to_string(),
            address: 0x3000,
            size: 16,
            is_plt: true,
        });

        // main -> func_a, main -> puts@plt, func_a -> puts@plt
        g.add_edge(main, func_a, CallEdge { call_site: 0x1010 });
        g.add_edge(main, puts_plt, CallEdge { call_site: 0x1020 });
        g.add_edge(func_a, puts_plt, CallEdge { call_site: 0x2010 });

        (g, main, func_a, puts_plt)
    }

    #[test]
    fn test_tree_construction_and_navigation() {
        let (g, main, func_a, puts_plt) = create_test_graph();
        let mut app = AppState::new(&g, main, "test_bin".to_string());

        // Root should be main
        assert_eq!(app.current_node, main);
        assert_eq!(app.history.len(), 0);

        // Visible rows should have root + 2 callees of main (func_a, puts@plt) + 1 callee of func_a (puts@plt)
        assert!(app.visible_rows.len() >= 3);
        assert_eq!(app.visible_rows[0].node_idx, main);

        // Navigation
        app.selected_index = 0;
        app.move_down();
        assert_eq!(app.selected_index, 1);
        app.move_up();
        assert_eq!(app.selected_index, 0);

        // Navigate to func_a (row 1) and jump into it
        app.selected_index = 1;
        let selected_target = app.visible_rows[1].node_idx;
        assert_eq!(selected_target, func_a);

        app.jump_into_selected(&g);

        // Current node should now be func_a, history should contain main
        assert_eq!(app.current_node, func_a);
        assert_eq!(app.history.len(), 1);
        assert_eq!(app.history[0], main);

        // In func_a, callees should contain puts@plt
        let callee_indices: Vec<_> = app.visible_rows.iter().map(|r| r.node_idx).collect();
        assert!(callee_indices.contains(&puts_plt));

        // Pop back to main
        app.pop_history(&g);
        assert_eq!(app.current_node, main);
        assert_eq!(app.history.len(), 0);
    }

    #[test]
    fn test_collapse_expand() {
        let (g, main, _func_a, _puts_plt) = create_test_graph();
        let mut app = AppState::new(&g, main, "test_bin".to_string());

        let total_initial = app.visible_rows.len();

        // Select root (index 0) which has children
        app.selected_index = 0;
        app.toggle_expand();

        // Now children should be collapsed, only root visible
        assert_eq!(app.visible_rows.len(), 1);

        // Expand root again
        app.toggle_expand();
        assert_eq!(app.visible_rows.len(), total_initial);
    }
}
