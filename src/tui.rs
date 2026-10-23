use std::collections::HashSet;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use ratatui::layout::{Constraint, Direction as LayoutDirection, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};
use ratatui::DefaultTerminal;

use crate::{CallEdge, CallGraph, DisassembledLine, FunctionNode};

/// Represents which pane currently has keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusedPane {
    /// Left pane: Incoming callers
    Callers,
    /// Center pane: Outgoing callee tree
    Callees,
}

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

/// State for the popup fuzzy search bar.
pub struct SearchState {
    pub is_open: bool,
    pub query: String,
    pub results: Vec<(NodeIndex, i64)>,
    pub selected_idx: usize,
    pub scroll_offset: usize,
}

impl SearchState {
    pub fn new() -> Self {
        Self {
            is_open: false,
            query: String::new(),
            results: Vec::new(),
            selected_idx: 0,
            scroll_offset: 0,
        }
    }

    pub fn open(&mut self, graph: &DiGraph<FunctionNode, CallEdge>) {
        self.is_open = true;
        self.query.clear();
        self.selected_idx = 0;
        self.scroll_offset = 0;
        self.update_results(graph);
    }

    pub fn update_results(&mut self, graph: &DiGraph<FunctionNode, CallEdge>) {
        let matcher = SkimMatcherV2::default();
        let query = self.query.trim();

        let mut matches = Vec::new();
        for idx in graph.node_indices() {
            let node = &graph[idx];
            if query.is_empty() {
                matches.push((idx, 0i64));
            } else if let Some(score) = matcher.fuzzy_match(&node.name, query) {
                matches.push((idx, score));
            }
        }

        if query.is_empty() {
            matches.sort_by(|a, b| {
                let node_a = &graph[a.0];
                let node_b = &graph[b.0];
                node_a
                    .is_plt
                    .cmp(&node_b.is_plt)
                    .then_with(|| node_a.name.cmp(&node_b.name))
            });
        } else {
            matches.sort_by(|a, b| {
                b.1.cmp(&a.1)
                    .then_with(|| graph[a.0].name.cmp(&graph[b.0].name))
            });
        }

        self.results = matches;
        if self.selected_idx >= self.results.len() {
            self.selected_idx = self.results.len().saturating_sub(1);
        }
    }

    pub fn move_down(&mut self) {
        if self.selected_idx + 1 < self.results.len() {
            self.selected_idx += 1;
        }
    }

    pub fn move_up(&mut self) {
        if self.selected_idx > 0 {
            self.selected_idx -= 1;
        }
    }
}

/// TUI Application state.
pub struct AppState {
    pub binary_name: String,
    pub current_node: NodeIndex,
    pub history: Vec<NodeIndex>,
    pub focused_pane: FocusedPane,
    pub selected_index: usize,
    pub caller_selected_index: usize,
    pub scroll_offset: usize,
    pub caller_scroll_offset: usize,
    pub disasm_scroll_offset: usize,
    pub collapsed_ids: HashSet<usize>,
    pub tree_root: TreeNode,
    pub visible_rows: Vec<VisibleRow>,
    pub cached_callers: Vec<(NodeIndex, u64)>,
    pub cached_disasm: Vec<DisassembledLine>,
    pub search: SearchState,
}

impl AppState {
    pub fn new(call_graph: &CallGraph, initial_node: NodeIndex, binary_name: String) -> Self {
        let mut app = Self {
            binary_name,
            current_node: initial_node,
            history: Vec::new(),
            focused_pane: FocusedPane::Callees,
            selected_index: 0,
            caller_selected_index: 0,
            scroll_offset: 0,
            caller_scroll_offset: 0,
            disasm_scroll_offset: 0,
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
            cached_callers: Vec::new(),
            cached_disasm: Vec::new(),
            search: SearchState::new(),
        };

        app.rebuild_tree(call_graph);
        app
    }

    /// Rebuilds callee tree, caller list, and disassembly cache for `current_node`.
    pub fn rebuild_tree(&mut self, call_graph: &CallGraph) {
        let mut next_id = 0;
        let mut ancestors = Vec::new();
        self.tree_root = Self::build_callee_tree(
            &call_graph.graph,
            self.current_node,
            0,
            3,
            None,
            &mut ancestors,
            &mut next_id,
        );

        self.refresh_visible_rows();

        if self.visible_rows.len() > 1 {
            self.selected_index = 1;
        } else {
            self.selected_index = 0;
        }

        // Cache incoming callers
        let mut callers: Vec<_> = call_graph
            .graph
            .edges_directed(self.current_node, Direction::Incoming)
            .map(|edge| (edge.source(), edge.weight().call_site))
            .collect();
        callers.sort_by_key(|(_, site)| *site);
        self.cached_callers = callers;
        self.caller_selected_index = 0;

        // Cache disassembly of current function
        let cur_func = &call_graph.graph[self.current_node];
        self.cached_disasm =
            call_graph.disassemble_function(cur_func.address, cur_func.size);

        self.scroll_offset = 0;
        self.caller_scroll_offset = 0;
        self.disasm_scroll_offset = 0;
        self.sync_disasm_to_selected();
    }

    /// Automatically scrolls disassembly to the callsite of the currently selected callee.
    pub fn sync_disasm_to_selected(&mut self) {
        if let Some(row) = self.visible_rows.get(self.selected_index) {
            if let Some(site) = row.call_site {
                if let Some(pos) = self.cached_disasm.iter().position(|l| l.ip == site) {
                    self.disasm_scroll_offset = pos.saturating_sub(4);
                }
            }
        }
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

    /// Toggle pane focus between Callers (Left) and Callees (Center).
    pub fn toggle_pane_focus(&mut self) {
        self.focused_pane = match self.focused_pane {
            FocusedPane::Callees => FocusedPane::Callers,
            FocusedPane::Callers => FocusedPane::Callees,
        };
    }

    /// Move selection down in the currently focused pane.
    pub fn move_down(&mut self) {
        match self.focused_pane {
            FocusedPane::Callees => {
                if self.selected_index + 1 < self.visible_rows.len() {
                    self.selected_index += 1;
                    self.sync_disasm_to_selected();
                }
            }
            FocusedPane::Callers => {
                if self.caller_selected_index + 1 < self.cached_callers.len() {
                    self.caller_selected_index += 1;
                }
            }
        }
    }

    /// Move selection up in the currently focused pane.
    pub fn move_up(&mut self) {
        match self.focused_pane {
            FocusedPane::Callees => {
                if self.selected_index > 0 {
                    self.selected_index -= 1;
                    self.sync_disasm_to_selected();
                }
            }
            FocusedPane::Callers => {
                if self.caller_selected_index > 0 {
                    self.caller_selected_index -= 1;
                }
            }
        }
    }

    /// Scroll disassembly pane down.
    pub fn disasm_scroll_down(&mut self) {
        self.disasm_scroll_offset = self.disasm_scroll_offset.saturating_add(6);
    }

    /// Scroll disassembly pane up.
    pub fn disasm_scroll_up(&mut self) {
        self.disasm_scroll_offset = self.disasm_scroll_offset.saturating_sub(6);
    }

    /// Toggle expansion of the selected tree item.
    pub fn toggle_expand(&mut self) {
        if self.focused_pane == FocusedPane::Callees {
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
    }

    /// Jump into the selected function from either the Callee Tree or Caller Pane.
    pub fn jump_into_selected(&mut self, call_graph: &CallGraph) {
        let target_node = match self.focused_pane {
            FocusedPane::Callees => {
                if let Some(row) = self.visible_rows.get(self.selected_index) {
                    Some(row.node_idx)
                } else {
                    None
                }
            }
            FocusedPane::Callers => {
                if let Some(&(caller_idx, _)) =
                    self.cached_callers.get(self.caller_selected_index)
                {
                    Some(caller_idx)
                } else {
                    None
                }
            }
        };

        if let Some(target) = target_node {
            if target != self.current_node {
                self.history.push(self.current_node);
                self.current_node = target;
                self.rebuild_tree(call_graph);
            }
        }
    }

    /// Pop back to the previous function from history (`Backspace`).
    pub fn pop_history(&mut self, call_graph: &CallGraph) {
        if let Some(prev) = self.history.pop() {
            self.current_node = prev;
            self.rebuild_tree(call_graph);
        }
    }
}

/// Runs the Ratatui + Crossterm interactive TUI.
pub fn run_tui(call_graph: &CallGraph, start_node: NodeIndex, binary_name: String) -> Result<()> {
    let mut terminal = ratatui::init();
    let mut app = AppState::new(call_graph, start_node, binary_name);

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
            let ev = event::read()?;
            if let Event::Key(key) = ev {
                // Ignore key release events to prevent double processing or missed repeats
                if key.kind == KeyEventKind::Release {
                    continue;
                }

                // Check if popup search is active
                if app.search.is_open {
                    match key.code {
                        KeyCode::Esc => {
                            app.search.is_open = false;
                        }
                        KeyCode::Char('c')
                            if key.modifiers.contains(KeyModifiers::CONTROL) =>
                        {
                            app.search.is_open = false;
                        }
                        KeyCode::Enter
                        | KeyCode::Char('\n')
                        | KeyCode::Char('\r') => {
                            if !app.search.results.is_empty() {
                                let (target_node, _) =
                                    app.search.results[app.search.selected_idx];
                                if target_node != app.current_node {
                                    app.history.push(app.current_node);
                                    app.current_node = target_node;
                                    app.rebuild_tree(call_graph);
                                }
                                app.search.is_open = false;
                            }
                        }
                        KeyCode::Down | KeyCode::Tab => {
                            app.search.move_down();
                        }
                        KeyCode::Up | KeyCode::BackTab => {
                            app.search.move_up();
                        }
                        KeyCode::Char('n')
                            if key.modifiers.contains(KeyModifiers::CONTROL) =>
                        {
                            app.search.move_down();
                        }
                        KeyCode::Char('p')
                            if key.modifiers.contains(KeyModifiers::CONTROL) =>
                        {
                            app.search.move_up();
                        }
                        KeyCode::Backspace
                        | KeyCode::Delete
                        | KeyCode::Char('\x08')
                        | KeyCode::Char('\x7f') => {
                            app.search.query.pop();
                            app.search.update_results(&call_graph.graph);
                            app.search.selected_idx = 0;
                            app.search.scroll_offset = 0;
                        }
                        KeyCode::Char(c) => {
                            app.search.query.push(c);
                            app.search.update_results(&call_graph.graph);
                            app.search.selected_idx = 0;
                            app.search.scroll_offset = 0;
                        }
                        _ => {}
                    }
                } else {
                    // Normal mode keybindings
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                            break;
                        }
                        KeyCode::Char('c')
                            if key.modifiers.contains(KeyModifiers::CONTROL) =>
                        {
                            break;
                        }
                        KeyCode::Char('/') => {
                            app.search.open(&call_graph.graph);
                        }
                        KeyCode::Tab | KeyCode::BackTab => {
                            app.toggle_pane_focus();
                        }
                        KeyCode::Left | KeyCode::Char('h') | KeyCode::Char('H') => {
                            app.focused_pane = FocusedPane::Callers;
                        }
                        KeyCode::Right | KeyCode::Char('l') | KeyCode::Char('L') => {
                            app.focused_pane = FocusedPane::Callees;
                        }
                        KeyCode::Char('j') | KeyCode::Char('J') | KeyCode::Down => {
                            app.move_down();
                        }
                        KeyCode::Char('k') | KeyCode::Char('K') | KeyCode::Up => {
                            app.move_up();
                        }
                        KeyCode::PageDown | KeyCode::Char(']') => {
                            app.disasm_scroll_down();
                        }
                        KeyCode::PageUp | KeyCode::Char('[') => {
                            app.disasm_scroll_up();
                        }
                        KeyCode::Char('d')
                            if key.modifiers.contains(KeyModifiers::CONTROL) =>
                        {
                            app.disasm_scroll_down();
                        }
                        KeyCode::Char('u')
                            if key.modifiers.contains(KeyModifiers::CONTROL) =>
                        {
                            app.disasm_scroll_up();
                        }
                        KeyCode::Enter
                        | KeyCode::Char('\n')
                        | KeyCode::Char('\r') => {
                            app.jump_into_selected(call_graph);
                        }
                        KeyCode::Backspace
                        | KeyCode::Char('\x08')
                        | KeyCode::Char('\x7f') => {
                            app.pop_history(call_graph);
                        }
                        KeyCode::Char(' ') => {
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

    // Horizontal split for the 3 Panes: Left (24%), Center (38%), Right (38%)
    let pane_chunks = Layout::default()
        .direction(LayoutDirection::Horizontal)
        .constraints([
            Constraint::Percentage(24),
            Constraint::Percentage(38),
            Constraint::Percentage(38),
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

    // 4. Render Right Pane (Disassembly of currently focused function using iced-x86)
    render_right_pane(frame, right_area, call_graph, app);

    // 5. Render Footer
    render_footer(frame, footer_area, app);

    // 6. Render Popup Fuzzy Search Modal (if active)
    if app.search.is_open {
        render_search_popup(frame, call_graph, &mut app.search);
    }
}

fn render_header(
    frame: &mut ratatui::Frame,
    area: Rect,
    call_graph: &CallGraph,
    app: &AppState,
) {
    let current_func = &call_graph.graph[app.current_node];

    let mut path_spans = Vec::new();
    path_spans.push(Span::styled(" Path: ", Style::default().fg(Color::DarkGray)));

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
    app: &mut AppState,
) {
    let is_focused = app.focused_pane == FocusedPane::Callers;
    let border_color = if is_focused {
        Color::Cyan
    } else {
        Color::Blue
    };

    let title = format!(
        " {}Callers [Incoming: {}] ",
        if is_focused { "[ACTIVE] " } else { "" },
        app.cached_callers.len()
    );

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(if is_focused {
            BorderType::Double
        } else {
            BorderType::Rounded
        })
        .border_style(Style::default().fg(border_color))
        .title(Span::styled(
            title,
            Style::default()
                .fg(if is_focused {
                    Color::Yellow
                } else {
                    Color::LightBlue
                })
                .add_modifier(Modifier::BOLD),
        ));

    let inner_height = area.height.saturating_sub(2) as usize;

    if app.caller_selected_index < app.caller_scroll_offset {
        app.caller_scroll_offset = app.caller_selected_index;
    } else if app.caller_selected_index >= app.caller_scroll_offset + inner_height / 2 {
        app.caller_scroll_offset = app.caller_selected_index + 1 - (inner_height / 2).max(1);
    }

    let mut lines = Vec::new();

    if app.cached_callers.is_empty() {
        lines.push(Line::from(Span::styled(
            " (No incoming callers - root entry)",
            Style::default().fg(Color::DarkGray).italic(),
        )));
    } else {
        for (idx, &(caller_idx, site)) in app
            .cached_callers
            .iter()
            .enumerate()
            .skip(app.caller_scroll_offset)
        {
            let is_selected = is_focused && idx == app.caller_selected_index;
            let caller = &call_graph.graph[caller_idx];

            let mut name_style = if caller.is_plt {
                Style::default().fg(Color::Magenta)
            } else {
                Style::default().fg(Color::Cyan)
            };

            if is_selected {
                name_style = name_style
                    .bg(Color::Rgb(30, 50, 70))
                    .add_modifier(Modifier::BOLD);
            }

            let prefix = if is_selected { ">> " } else { "   " };

            lines.push(Line::from(vec![
                Span::styled(
                    prefix,
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
                Span::styled(&caller.name, name_style),
            ]));
            lines.push(Line::from(vec![
                Span::styled(
                    format!("      at 0x{:x} [call: 0x{:x}]", caller.address, site),
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
    let is_focused = app.focused_pane == FocusedPane::Callees;
    let border_color = if is_focused {
        Color::LightGreen
    } else {
        Color::Green
    };

    let title = format!(
        " {}Callee Tree (Outgoing ≤ Depth 3) [{}/{}] ",
        if is_focused { "[ACTIVE] " } else { "" },
        if app.visible_rows.is_empty() {
            0
        } else {
            app.selected_index + 1
        },
        app.visible_rows.len()
    );

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(if is_focused {
            BorderType::Double
        } else {
            BorderType::Rounded
        })
        .border_style(Style::default().fg(border_color))
        .title(Span::styled(
            title,
            Style::default()
                .fg(if is_focused {
                    Color::Yellow
                } else {
                    Color::LightGreen
                })
                .add_modifier(Modifier::BOLD),
        ));

    let inner_height = area.height.saturating_sub(2) as usize;

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
        let is_selected = is_focused && idx == app.selected_index;
        let is_passive_selected = !is_focused && idx == app.selected_index;
        let node = &call_graph.graph[row.node_idx];

        let mut spans = Vec::new();

        if is_selected {
            spans.push(Span::styled(
                ">> ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ));
        } else if is_passive_selected {
            spans.push(Span::styled(
                ">  ",
                Style::default().fg(Color::DarkGray),
            ));
        } else {
            spans.push(Span::raw("   "));
        }

        for _ in 0..row.depth {
            spans.push(Span::styled("│  ", Style::default().fg(Color::DarkGray)));
        }

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
                .bg(Color::Rgb(30, 50, 70))
                .add_modifier(Modifier::BOLD);
        } else if is_passive_selected {
            name_style = name_style.bg(Color::Rgb(20, 25, 30));
        }

        spans.push(Span::styled(&node.name, name_style));

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
    app: &mut AppState,
) {
    let current_func = &call_graph.graph[app.current_node];

    let in_degree = app.cached_callers.len();
    let out_degree = call_graph
        .graph
        .edges_directed(app.current_node, Direction::Outgoing)
        .count();

    let title = format!(
        " Disassembly: {} (0x{:x}, {} B) [In: {}, Out: {}] ",
        current_func.name, current_func.address, current_func.size, in_degree, out_degree
    );

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Magenta))
        .title(Span::styled(
            title,
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD),
        ));

    let inner_height = area.height.saturating_sub(2) as usize;

    let max_scroll = app.cached_disasm.len().saturating_sub(inner_height);
    if app.disasm_scroll_offset > max_scroll {
        app.disasm_scroll_offset = max_scroll;
    }

    let mut lines = Vec::new();

    if app.cached_disasm.is_empty() {
        lines.push(Line::from(Span::styled(
            " (No executable machine instructions found for this function)",
            Style::default().fg(Color::DarkGray).italic(),
        )));
    } else {
        for line in app
            .cached_disasm
            .iter()
            .skip(app.disasm_scroll_offset)
            .take(inner_height)
        {
            if line.is_call {
                // Highlight CALL instruction lines in bold yellow!
                let mut spans = vec![
                    Span::styled(
                        format!(" 0x{:08x}:  ", line.ip),
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{:<26}", line.instruction_text),
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                ];
                if let Some(target_name) = &line.target_symbol {
                    spans.push(Span::styled(
                        format!(" ; -> {}", target_name),
                        Style::default()
                            .fg(Color::LightYellow)
                            .add_modifier(Modifier::BOLD),
                    ));
                }
                lines.push(Line::from(spans));
            } else {
                // Regular instructions
                let spans = vec![
                    Span::styled(
                        format!(" 0x{:08x}:  ", line.ip),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        &line.instruction_text,
                        Style::default().fg(Color::White),
                    ),
                ];
                lines.push(Line::from(spans));
            }
        }
    }

    let para = Paragraph::new(lines).block(block);
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
            format!("[Backspace] Pop (#{})", app.history.len()),
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        )
    };

    let help_spans = vec![
        Span::styled(" [/] ", Style::default().fg(Color::Yellow).bold()),
        Span::styled("Search  ", Style::default().fg(Color::DarkGray)),
        Span::styled("[Tab] ", Style::default().fg(Color::Cyan).bold()),
        Span::styled("Switch Pane  ", Style::default().fg(Color::DarkGray)),
        Span::styled("[j/k] ", Style::default().fg(Color::White).bold()),
        Span::styled("Nav  ", Style::default().fg(Color::DarkGray)),
        Span::styled("[Space] ", Style::default().fg(Color::White).bold()),
        Span::styled("Fold  ", Style::default().fg(Color::DarkGray)),
        Span::styled("[Enter] ", Style::default().fg(Color::White).bold()),
        Span::styled("Jump  ", Style::default().fg(Color::DarkGray)),
        history_hint,
        Span::styled("  ", Style::default()),
        Span::styled("[[/]] ", Style::default().fg(Color::Magenta).bold()),
        Span::styled("Disasm Scroll  ", Style::default().fg(Color::DarkGray)),
        Span::styled("[q/Esc] ", Style::default().fg(Color::Red).bold()),
        Span::styled("Quit", Style::default().fg(Color::DarkGray)),
    ];

    let para = Paragraph::new(Line::from(help_spans)).block(block);
    frame.render_widget(para, area);
}

/// Helper to center a rectangular area on screen.
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(LayoutDirection::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(LayoutDirection::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// Renders the modal popup fuzzy search dialog.
fn render_search_popup(
    frame: &mut ratatui::Frame,
    call_graph: &CallGraph,
    search: &mut SearchState,
) {
    let area = centered_rect(75, 70, frame.area());
    frame.render_widget(Clear, area);

    let title = format!(
        " 🔍 Fuzzy Symbol Search [{}/{}] (Enter: Jump, Esc: Close) ",
        if search.results.is_empty() {
            0
        } else {
            search.selected_idx + 1
        },
        search.results.len()
    );

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .title(Span::styled(
            title,
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));

    // Render outer block first
    frame.render_widget(block, area);

    let inner_layout = Layout::default()
        .direction(LayoutDirection::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(4)])
        .margin(1)
        .split(area);

    let input_area = inner_layout[0];
    let results_area = inner_layout[1];

    // Search query box
    let input_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Type to filter demangled symbols ");

    let input_line = Line::from(vec![
        Span::styled(" > ", Style::default().fg(Color::Yellow).bold()),
        Span::styled(&search.query, Style::default().fg(Color::White).bold()),
        Span::styled("█", Style::default().fg(Color::Yellow)),
    ]);
    frame.render_widget(Paragraph::new(input_line).block(input_block), input_area);

    // Filtered results list
    let list_height = results_area.height as usize;
    if search.selected_idx < search.scroll_offset {
        search.scroll_offset = search.selected_idx;
    } else if search.selected_idx >= search.scroll_offset + list_height {
        search.scroll_offset = search.selected_idx + 1 - list_height;
    }

    let mut result_lines = Vec::new();
    for (i, &(node_idx, score)) in search
        .results
        .iter()
        .enumerate()
        .skip(search.scroll_offset)
        .take(list_height)
    {
        let is_selected = i == search.selected_idx;
        let node = &call_graph.graph[node_idx];

        let mut spans = Vec::new();
        if is_selected {
            spans.push(Span::styled(
                ">> ",
                Style::default().fg(Color::Yellow).bold(),
            ));
        } else {
            spans.push(Span::raw("   "));
        }

        let name_style = if is_selected {
            Style::default()
                .fg(Color::Yellow)
                .bg(Color::Rgb(30, 50, 70))
                .bold()
        } else if node.is_plt {
            Style::default().fg(Color::Magenta)
        } else {
            Style::default().fg(Color::White)
        };

        spans.push(Span::styled(&node.name, name_style));
        spans.push(Span::styled(
            format!("  (0x{:x})", node.address),
            Style::default().fg(Color::DarkGray),
        ));

        if node.is_plt {
            spans.push(Span::styled(
                " [PLT]",
                Style::default().fg(Color::Magenta).bold(),
            ));
        }

        if score > 0 {
            spans.push(Span::styled(
                format!("  score: {}", score),
                Style::default().fg(Color::DarkGray),
            ));
        }

        result_lines.push(Line::from(spans));
    }

    if result_lines.is_empty() {
        result_lines.push(Line::from(Span::styled(
            " No matching symbols found",
            Style::default().fg(Color::DarkGray).italic(),
        )));
    }

    frame.render_widget(Paragraph::new(result_lines), results_area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CallEdge, FunctionNode, SymbolMap};
    use petgraph::graph::DiGraph;

    fn create_test_call_graph() -> (CallGraph, NodeIndex, NodeIndex, NodeIndex) {
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

        g.add_edge(main, func_a, CallEdge { call_site: 0x1010 });
        g.add_edge(main, puts_plt, CallEdge { call_site: 0x1020 });
        g.add_edge(func_a, puts_plt, CallEdge { call_site: 0x2010 });

        let cg = CallGraph {
            graph: g,
            node_indices: std::collections::HashMap::new(),
            symbol_map: SymbolMap::new(),
            exec_sections: Vec::new(),
        };

        (cg, main, func_a, puts_plt)
    }

    #[test]
    fn test_tree_construction_and_navigation() {
        let (cg, main, func_a, puts_plt) = create_test_call_graph();
        let mut app = AppState::new(&cg, main, "test_bin".to_string());

        assert_eq!(app.current_node, main);
        assert_eq!(app.history.len(), 0);

        assert!(app.visible_rows.len() >= 3);
        assert_eq!(app.visible_rows[0].node_idx, main);

        app.selected_index = 0;
        app.move_down();
        assert_eq!(app.selected_index, 1);
        app.move_up();
        assert_eq!(app.selected_index, 0);

        app.selected_index = 1;
        let selected_target = app.visible_rows[1].node_idx;
        assert_eq!(selected_target, func_a);

        app.jump_into_selected(&cg);

        assert_eq!(app.current_node, func_a);
        assert_eq!(app.history.len(), 1);
        assert_eq!(app.history[0], main);

        let callee_indices: Vec<_> = app.visible_rows.iter().map(|r| r.node_idx).collect();
        assert!(callee_indices.contains(&puts_plt));

        app.pop_history(&cg);
        assert_eq!(app.current_node, main);
        assert_eq!(app.history.len(), 0);
    }

    #[test]
    fn test_collapse_expand() {
        let (cg, main, _func_a, _puts_plt) = create_test_call_graph();
        let mut app = AppState::new(&cg, main, "test_bin".to_string());

        let total_initial = app.visible_rows.len();

        app.selected_index = 0;
        app.toggle_expand();
        assert_eq!(app.visible_rows.len(), 1);

        app.toggle_expand();
        assert_eq!(app.visible_rows.len(), total_initial);
    }

    #[test]
    fn test_fuzzy_search_state() {
        let (cg, _main, func_a, puts_plt) = create_test_call_graph();
        let mut search = SearchState::new();

        search.open(&cg.graph);
        assert!(search.is_open);
        assert_eq!(search.results.len(), 3);

        search.query = "puts".to_string();
        search.update_results(&cg.graph);
        assert!(!search.results.is_empty());
        assert_eq!(search.results[0].0, puts_plt);

        search.query = "func".to_string();
        search.update_results(&cg.graph);
        assert_eq!(search.results[0].0, func_a);

        search.selected_idx = 0;
        search.move_down();
        search.move_up();
        assert_eq!(search.selected_idx, 0);
    }
}
