//! Terminal presentation only. User-controlled strings always cross `safe_text`.
//!
//! Render strings and ratatui buffers are transient plaintext allocations, not
//! guaranteed zeroizing memory. Masked values never enter those allocations;
//! explicitly revealed values do. Clearing/redrawing is best effort, not a claim
//! that a terminal, compositor, allocator, or scrollback securely erases secrets.
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use unicode_width::UnicodeWidthChar;

use crate::{
    app::{App, Mode, Pane},
    editor::{Editor, EditorControl, TextInput},
    model::Template,
    theme::{Palette, Theme},
};

const MASK: &str = "************";
const LOGO: [&str; 4] = [
    r" /\_/\       .----. ",
    r"( o.o )      |    | ",
    r" > ^ <      [  ::  ]",
    r"             '----' ",
];

/// Make terminal controls, direction overrides, and invisible formatting visible.
/// Newlines are escaped here; only intentional multiline widgets split them first.
pub fn safe_text(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{1b}' => output.push_str("<ESC>"),
            c if c.is_control()
                || matches!(c, '\u{ad}' | '\u{61c}' | '\u{180e}' | '\u{200b}'..='\u{200f}'
                    | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}'
                    | '\u{fff9}'..='\u{fffb}' | '\u{e0000}'..='\u{e007f}') =>
            {
                use std::fmt::Write;
                let _ = write!(output, "\\u{{{:04X}}}", c as u32);
            }
            c => output.push(c),
        }
    }
    output
}

fn style(color: ratatui::style::Color) -> Style {
    Style::default().fg(color)
}

fn panel(title: impl Into<String>, focused: bool, p: Palette) -> Block<'static> {
    Block::default()
        .title(Line::from(format!(" {} ", title.into())))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(style(if focused { p.mauve } else { p.surface2 }))
        .title_style(style(if focused { p.lavender } else { p.subtext0 }))
        .style(Style::default().fg(p.text).bg(p.base))
}

fn inset(area: Rect, horizontal: u16, vertical: u16) -> Rect {
    let x = horizontal.min(area.width / 2);
    let y = vertical.min(area.height / 2);
    Rect::new(
        area.x + x,
        area.y + y,
        area.width - 2 * x,
        area.height - 2 * y,
    )
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

pub fn render(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let p = app.theme.palette();
    frame.render_widget(
        Block::default().style(Style::default().bg(p.base).fg(p.text)),
        area,
    );
    if area.width < 36 || area.height < 12 {
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled("SIMPLECRYPT", style(p.mauve).add_modifier(Modifier::BOLD)),
                Line::from("Small vault. Quiet secrets."),
                Line::from("Enlarge to at least 36 x 12."),
                Line::styled("Ctrl-Q quits safely.", style(p.subtext0)),
            ])
            .wrap(Wrap { trim: false }),
            area,
        );
        return;
    }
    let rows = Layout::vertical([
        Constraint::Length(if area.width >= 80 { 3 } else { 2 }),
        Constraint::Min(1),
        Constraint::Length(1),
        Constraint::Length(2),
    ])
    .split(area);
    header(frame, rows[0], app, p);
    match app.mode {
        Mode::Create | Mode::Locked => auth(frame, rows[1], app, p),
        Mode::Edit => editor(frame, rows[1], app, p),
        _ => browse(frame, rows[1], app, p),
    }
    footer(frame, rows[2], rows[3], app, p);
    match app.mode {
        Mode::Templates | Mode::Delete | Mode::Help | Mode::Themes => modal(frame, rows[1], app, p),
        _ => {}
    }
}

fn header(frame: &mut Frame, area: Rect, app: &App, p: Palette) {
    let locked = matches!(app.mode, Mode::Create | Mode::Locked);
    let title = Line::from(vec![
        Span::styled(
            "  /\\_/\\  SIMPLECRYPT",
            style(p.mauve).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            if locked {
                "   [ LOCKED ]"
            } else {
                "   [ OPEN ]"
            },
            style(if locked { p.peach } else { p.green }),
        ),
    ]);
    let mut lines = vec![title];
    if area.height > 2 {
        lines.push(Line::styled(
            "          Small vault. Quiet secrets.",
            style(p.subtext0),
        ));
    }
    frame.render_widget(
        Paragraph::new(lines).style(Style::default().bg(p.mantle)),
        area,
    );
    if area.width >= 80 {
        let right = Rect::new(area.right().saturating_sub(29), area.y, 27, area.height - 1);
        let state = if locked {
            "local-first · encrypted at rest".to_owned()
        } else {
            format!("{} records · {}", app.records().len(), app.theme.label())
        };
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(state, style(p.subtext0)),
                Line::styled(
                    if locked {
                        "your keys, your vault"
                    } else {
                        "L lock   ? help   t theme"
                    },
                    style(p.overlay2),
                ),
            ])
            .alignment(Alignment::Right),
            right,
        );
    }
}

fn footer(frame: &mut Frame, status: Rect, keys: Rect, app: &App, p: Palette) {
    let message = format!(
        " {} {}",
        if app.is_error { "!" } else { "·" },
        safe_text(&app.status)
    );
    frame.render_widget(
        Paragraph::new(message)
            .style(style(if app.is_error { p.red } else { p.subtext1 }).bg(p.mantle)),
        status,
    );
    let (primary, secondary) = match app.mode {
        Mode::Create => (
            "Tab switch password / confirmation · Enter next / create",
            "Esc clears both · Ctrl-Q quit · no password recovery",
        ),
        Mode::Locked => (
            "Enter unlock · Esc clear · Ctrl-Q quit",
            "Password stays hidden; its length is not displayed.",
        ),
        Mode::Browse => (
            "j/k move · h/l panes · / search · a add · e edit · d delete",
            "r reveal 10s · PgUp/PgDn scroll · L lock · t theme · ? help · q quit",
        ),
        Mode::Search => (
            "Type to filter record labels · Enter apply · Esc restore",
            "Only labels are searched; secret values are never searched.",
        ),
        Mode::Edit => (
            "Tab / Shift-Tab focus · Enter / Space activate · Ctrl-S save",
            "Esc cancel · text: arrows / Home / End · Ctrl-U clear",
        ),
        Mode::Templates => (
            "j/k choose template · Enter create draft · Esc cancel",
            "Templates are a starting point. Every field is editable.",
        ),
        Mode::Delete => (
            "y permanently delete · n / Esc keep record",
            "Deletion is saved immediately. There is no undo.",
        ),
        Mode::Help => (
            "Esc / Enter / ? close help · L lock",
            "Ctrl-Q quits from any screen; unsaved drafts are discarded.",
        ),
        Mode::Themes => (
            "j/k choose palette · Enter apply · Esc cancel",
            "Theme changes are session-only; use --theme at launch.",
        ),
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(format!(" {primary}"), style(p.lavender)),
            Line::styled(format!(" {secondary}"), style(p.subtext0)),
        ]),
        keys,
    );
}

fn auth(frame: &mut Frame, area: Rect, app: &App, p: Palette) {
    let create = app.mode == Mode::Create;
    if area.height < 13 {
        let rows = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(inset(area, 1, 0));
        frame.render_widget(
            Paragraph::new(if create {
                "Create vault · use 12+ characters"
            } else {
                "Welcome back · unlock your vault"
            })
            .style(style(p.mauve)),
            rows[0],
        );
        let confirmation = create && app.auth_focus == 1;
        input(
            frame,
            rows[1],
            if confirmation {
                "Confirm master password"
            } else {
                "Master password"
            },
            if confirmation {
                &app.confirmation
            } else {
                &app.master
            },
            true,
            true,
            false,
            p,
        );
        frame.render_widget(Paragraph::new(if create { "Tab switches inputs. Enter next / create.\nType the same password twice. No recovery." } else { "Enter unlocks. Esc clears.\nPassword length is never displayed." }).wrap(Wrap { trim: false }).style(style(p.subtext0)), rows[2]);
        return;
    }
    let desired = if create { 23 } else { 20 };
    let card = centered(inset(area, 1, 0), 62, desired);
    let block = panel(
        if create {
            "A little home for your secrets"
        } else {
            "Welcome back"
        },
        true,
        p,
    );
    let inner = inset(block.inner(card), 2, 0);
    frame.render_widget(block, card);
    let logo_height = if inner.height >= 18 {
        7
    } else if inner.height >= 13 {
        3
    } else {
        0
    };
    let rows = Layout::vertical([
        Constraint::Length(logo_height),
        Constraint::Length(2),
        Constraint::Length(3),
        Constraint::Length(if create { 3 } else { 0 }),
        Constraint::Min(0),
    ])
    .split(inner);
    if logo_height > 3 {
        let mut logo: Vec<Line> = LOGO
            .iter()
            .map(|line| Line::styled(*line, style(p.peach)))
            .collect();
        logo.push(Line::styled(
            "SIMPLECRYPT",
            style(p.mauve).add_modifier(Modifier::BOLD),
        ));
        logo.push(Line::styled(
            "Small vault. Quiet secrets.",
            style(p.subtext0),
        ));
        frame.render_widget(Paragraph::new(logo).alignment(Alignment::Center), rows[0]);
    } else if logo_height > 0 {
        frame.render_widget(
            Paragraph::new("SIMPLECRYPT\nSmall vault. Quiet secrets.")
                .alignment(Alignment::Center)
                .style(style(p.mauve)),
            rows[0],
        );
    }
    frame.render_widget(
        Paragraph::new(if create {
            "Create a master password.\nUse 12+ characters; a unique passphrase is best."
        } else {
            "Your vault is locked.\nEnter your master password to open it."
        })
        .style(style(p.subtext1)),
        rows[1],
    );
    input(
        frame,
        rows[2],
        "Master password",
        &app.master,
        app.auth_focus == 0,
        true,
        false,
        p,
    );
    if create {
        input(
            frame,
            rows[3],
            "Confirm master password",
            &app.confirmation,
            app.auth_focus == 1,
            true,
            false,
            p,
        );
    }
    let mut help = vec![
        Line::styled(
            if create {
                "Enter moves to confirmation, then creates the vault."
            } else {
                "Enter unlocks your vault."
            },
            style(p.lavender),
        ),
        Line::styled(
            if create {
                "Type the same password twice. There is no recovery."
            } else {
                "Everything stays local. Nothing is sent to a server."
            },
            style(p.subtext0),
        ),
        Line::from(""),
    ];
    help.push(Line::styled(
        format!(
            "Vault: {}",
            safe_text(&app.file.path().display().to_string())
        ),
        style(p.overlay2),
    ));
    frame.render_widget(Paragraph::new(help).wrap(Wrap { trim: false }), rows[4]);
}

fn browse(frame: &mut Frame, area: Rect, app: &App, p: Palette) {
    let rows =
        Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).split(inset(area, 1, 0));
    if app.mode == Mode::Search {
        input(
            frame,
            rows[0],
            "/ Search labels",
            &app.query,
            true,
            false,
            false,
            p,
        );
    } else {
        let filter = if app.query.value.is_empty() {
            "/  Search your record labels".to_owned()
        } else {
            format!("/  {}    · Esc clears", safe_text(&app.query.value))
        };
        frame.render_widget(
            Paragraph::new(filter).style(style(p.subtext0)).block(panel(
                "Find a little faster",
                false,
                p,
            )),
            rows[0],
        );
    }
    if area.width >= 80 {
        let panes = Layout::horizontal([Constraint::Percentage(33), Constraint::Percentage(67)])
            .split(rows[1]);
        record_list(frame, panes[0], app, p);
        details(frame, panes[1], app, p);
    } else if app.pane == Pane::Records || app.mode == Mode::Search {
        record_list(frame, rows[1], app, p);
    } else {
        details(frame, rows[1], app, p);
    }
}

fn record_list(frame: &mut Frame, area: Rect, app: &App, p: Palette) {
    let indices = app.filtered_indices();
    let focused = app.pane == Pane::Records && app.mode == Mode::Browse;
    let title = format!("Records · {}/{}", indices.len(), app.records().len());
    let block = panel(title, focused, p)
        .title_bottom(Line::styled(" l / Enter opens fields ", style(p.subtext0)));
    if indices.is_empty() {
        let text = if app.records().is_empty() {
            "\nA quiet place, ready for you.\n\nPress a to add your first record."
        } else {
            "\nNo matching labels.\n\n/ changes the search.\nEsc clears the filter."
        };
        frame.render_widget(
            Paragraph::new(text)
                .wrap(Wrap { trim: false })
                .block(block)
                .style(style(p.subtext0)),
            area,
        );
        return;
    }
    let items: Vec<ListItem> = indices
        .iter()
        .map(|index| {
            let record = &app.records()[*index];
            ListItem::new(vec![
                Line::from(safe_text(&record.label)),
                Line::styled(format!("{} fields", record.fields.len()), style(p.subtext0)),
                Line::from(""),
            ])
        })
        .collect();
    let list = List::new(items)
        .block(block)
        .highlight_symbol("› ")
        .highlight_style(
            style(p.lavender)
                .bg(p.surface0)
                .add_modifier(Modifier::BOLD),
        );
    // Recomputed each frame: the selected item always enters the viewport.
    let mut state = ListState::default().with_selected(Some(app.selected.min(indices.len() - 1)));
    frame.render_stateful_widget(list, area, &mut state);
}

fn details(frame: &mut Frame, area: Rect, app: &App, p: Palette) {
    let Some(record) = app.current_record() else {
        frame.render_widget(Paragraph::new("\nSelect a record to see its fields.\n\nA small vault for the things worth keeping.")
            .wrap(Wrap { trim: false }).style(style(p.subtext0)).block(panel("Your record", false, p)), area);
        return;
    };
    let focused = app.pane == Pane::Fields && app.mode == Mode::Browse;
    let block = panel(safe_text(&record.label), focused, p).title_bottom(Line::styled(
        " h records · j/k fields · PgUp/PgDn text ",
        style(p.subtext0),
    ));
    let inner = inset(block.inner(area), 1, 0);
    frame.render_widget(block, area);
    if inner.is_empty() {
        return;
    }
    let rows = Layout::vertical([Constraint::Length(2), Constraint::Min(0)]).split(inner);
    frame.render_widget(
        Paragraph::new(format!(
            "{} fields  ·  {} secret  ·  field {}/{}",
            record.fields.len(),
            record.fields.iter().filter(|f| f.secret).count(),
            if record.fields.is_empty() {
                0
            } else {
                app.selected_field + 1
            },
            record.fields.len()
        ))
        .style(style(p.subtext0)),
        rows[0],
    );
    if record.fields.is_empty() {
        frame.render_widget(
            Paragraph::new("No fields yet. Press e to make this record yours.")
                .wrap(Wrap { trim: false })
                .style(style(p.subtext0)),
            rows[1],
        );
        return;
    }
    let selected = app.selected_field.min(record.fields.len() - 1);
    let mut lines = Vec::new();
    let mut selected_start = 0;
    let mut selected_end = 0;
    for (index, field) in record.fields.iter().enumerate() {
        let is_selected = index == selected;
        if is_selected {
            selected_start = lines.len();
        }
        let active = if is_selected {
            style(p.lavender).bg(p.surface0)
        } else {
            style(p.subtext1)
        };
        lines.push(Line::from(vec![
            Span::styled(if is_selected { "› " } else { "  " }, active),
            Span::styled(safe_text(&field.name), active.add_modifier(Modifier::BOLD)),
            Span::styled(format!("  [{}]", field.kind.label()), style(p.teal)),
            Span::styled(
                if field.secret {
                    " [secret]"
                } else {
                    " [visible]"
                },
                style(if field.secret { p.peach } else { p.overlay2 }),
            ),
        ]));
        // Do not even copy a secret into a render string unless explicitly revealed.
        let reveal = field.secret && app.revealed() && is_selected && app.mode == Mode::Browse;
        let content = if field.secret && !reveal {
            vec![MASK.to_owned()]
        } else if field.value.is_empty() {
            vec!["(empty)".to_owned()]
        } else {
            wrapped_safe(&field.value, inner.width.saturating_sub(2).max(1) as usize)
        };
        for text in content {
            lines.push(Line::styled(
                format!("  {text}"),
                style(if reveal {
                    p.peach
                } else if field.secret {
                    p.overlay2
                } else {
                    p.text
                }),
            ));
        }
        if reveal {
            lines.push(Line::styled("  Revealed briefly · r hides", style(p.peach)));
        }
        if is_selected {
            selected_end = lines.len();
        }
        lines.push(Line::from(""));
    }
    let height = rows[1].height as usize;
    let base = if selected_end <= height {
        0
    } else if selected_end - selected_start <= height {
        selected_end.saturating_sub(height)
    } else {
        selected_start
    };
    let start = if app.detail_scroll > 0 {
        selected_start
            + app
                .detail_scroll
                .min(selected_end.saturating_sub(selected_start + 1))
    } else {
        base
    };
    // Skip rows instead of Paragraph::scroll's u16 offset, supporting very long notes.
    let visible: Vec<Line> = lines.into_iter().skip(start).take(height).collect();
    frame.render_widget(Paragraph::new(visible), rows[1]);
}

/// Character wrapping is deliberate: addresses and long tokens must remain readable.
fn wrapped_safe(text: &str, width: usize) -> Vec<String> {
    let mut rows = Vec::new();
    for raw in text.split('\n') {
        let safe = safe_text(raw);
        let mut line = String::new();
        let mut used = 0;
        for c in safe.chars() {
            let w = c.width().unwrap_or(0);
            if used + w > width && !line.is_empty() {
                rows.push(std::mem::take(&mut line));
                used = 0;
            }
            line.push(c);
            used += w;
        }
        rows.push(line);
    }
    rows
}

fn editor(frame: &mut Frame, area: Rect, app: &App, p: Palette) {
    let Some(editor) = &app.editor else {
        return;
    };
    let area = inset(area, 1, 0);
    if area.height < 15 {
        compact_editor(frame, area, editor, p);
        return;
    }
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(9),
        Constraint::Length(3),
    ])
    .split(area);
    input(
        frame,
        rows[0],
        if editor.existing {
            "Edit record · title"
        } else {
            "New record · title"
        },
        &editor.label,
        editor.focus == EditorControl::Label,
        false,
        false,
        p,
    );
    if area.width >= 78 {
        let columns = Layout::horizontal([Constraint::Percentage(28), Constraint::Percentage(72)])
            .split(rows[1]);
        editor_fields(frame, columns[0], editor, p);
        editor_detail(frame, columns[1], editor, p);
    } else if editor.focus == EditorControl::FieldList {
        editor_fields(frame, rows[1], editor, p);
    } else {
        editor_detail(frame, rows[1], editor, p);
    }
    editor_actions(frame, rows[2], editor, p);
}

fn editor_fields(frame: &mut Frame, area: Rect, editor: &Editor, p: Palette) {
    let block = panel(
        format!("Fields · {}", editor.record.fields.len()),
        editor.focus == EditorControl::FieldList,
        p,
    )
    .title_bottom(Line::styled(" j/k select · Enter edit ", style(p.subtext0)));
    let items: Vec<ListItem> = editor
        .record
        .fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let name = if index == editor.field {
                &editor.name.value
            } else {
                &field.name
            };
            ListItem::new(vec![
                Line::from(safe_text(name)),
                Line::styled(
                    format!(
                        "{}{}",
                        field.kind.label(),
                        if field.secret { " · secret" } else { "" }
                    ),
                    style(p.subtext0),
                ),
            ])
        })
        .collect();
    if items.is_empty() {
        frame.render_widget(
            Paragraph::new("\nNo fields yet.\nTab to [Add field].")
                .style(style(p.subtext0))
                .block(block),
            area,
        );
    } else {
        let mut state = ListState::default().with_selected(Some(editor.field.min(items.len() - 1)));
        frame.render_stateful_widget(
            List::new(items)
                .block(block)
                .highlight_symbol("› ")
                .highlight_style(style(p.lavender).bg(p.surface0)),
            area,
            &mut state,
        );
    }
}

fn editor_detail(frame: &mut Frame, area: Rect, editor: &Editor, p: Palette) {
    let Some(field) = editor.record.fields.get(editor.field) else {
        frame.render_widget(Paragraph::new("\nA blank canvas.\n\nTab to Add field, then press Enter.\nGive every detail a name, type, and value.")
            .wrap(Wrap { trim: false }).style(style(p.subtext0)).block(panel("Build your record", false, p)), area);
        return;
    };
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(3),
    ])
    .split(area);
    input(
        frame,
        rows[0],
        &format!("Field {} · name", editor.field + 1),
        &editor.name,
        editor.focus == EditorControl::Name,
        false,
        false,
        p,
    );
    let choices =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(rows[1]);
    frame.render_widget(
        Paragraph::new(format!("‹ {} ›", field.kind.label()))
            .style(style(p.teal))
            .block(panel("Type · ←/→", editor.focus == EditorControl::Kind, p)),
        choices[0],
    );
    frame.render_widget(
        Paragraph::new(if field.secret {
            "[x] Secret / hidden"
        } else {
            "[ ] Visible text"
        })
        .style(style(if field.secret { p.peach } else { p.subtext1 }))
        .block(panel(
            "Secret · Space",
            editor.focus == EditorControl::Secret,
            p,
        )),
        choices[1],
    );
    input(
        frame,
        rows[2],
        if field.secret {
            "Value · always masked in editor"
        } else if editor.multiline() {
            "Value · Enter newline · arrows navigate"
        } else {
            "Value"
        },
        &editor.value,
        editor.focus == EditorControl::Value,
        field.secret,
        editor.multiline(),
        p,
    );
}

fn control_label(control: EditorControl) -> &'static str {
    match control {
        EditorControl::Label => "Record title",
        EditorControl::FieldList => "Field list",
        EditorControl::Name => "Field name",
        EditorControl::Kind => "Field type",
        EditorControl::Secret => "Secret toggle",
        EditorControl::Value => "Field value",
        EditorControl::Generate => "Generate",
        EditorControl::Add => "Add field",
        EditorControl::Remove => "Remove",
        EditorControl::MoveUp => "Move up",
        EditorControl::MoveDown => "Move down",
        EditorControl::Save => "Save",
        EditorControl::Cancel => "Cancel",
    }
}

fn editor_actions(frame: &mut Frame, area: Rect, editor: &Editor, p: Palette) {
    let mut rows = Vec::new();
    let mut spans = Vec::new();
    let mut used = 0;
    for control in EditorControl::ALL.into_iter().skip(6) {
        let label = format!(" [{}] ", control_label(control));
        if used + label.len() > area.width as usize && !spans.is_empty() {
            rows.push(Line::from(std::mem::take(&mut spans)));
            used = 0;
        }
        used += label.len();
        let selected = editor.focus == control;
        spans.push(Span::styled(
            label,
            if selected {
                style(p.base).bg(p.mauve).add_modifier(Modifier::BOLD)
            } else {
                style(if control == EditorControl::Save {
                    p.green
                } else if control == EditorControl::Remove {
                    p.red
                } else {
                    p.subtext1
                })
            },
        ));
    }
    rows.push(Line::from(spans));
    frame.render_widget(
        Paragraph::new(rows).style(Style::default().bg(p.mantle)),
        area,
    );
}

fn compact_editor(frame: &mut Frame, area: Rect, editor: &Editor, p: Palette) {
    let step = EditorControl::ALL
        .iter()
        .position(|c| *c == editor.focus)
        .unwrap_or(0)
        + 1;
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(2),
    ])
    .split(area);
    frame.render_widget(
        Paragraph::new(format!(
            "Draft · {step}/13 · {}",
            control_label(editor.focus)
        ))
        .style(style(p.lavender)),
        rows[0],
    );
    match editor.focus {
        EditorControl::Label => input(
            frame,
            rows[1],
            "Record title",
            &editor.label,
            true,
            false,
            false,
            p,
        ),
        EditorControl::FieldList => editor_fields(frame, rows[1], editor, p),
        EditorControl::Name => input(
            frame,
            rows[1],
            "Field name",
            &editor.name,
            true,
            false,
            false,
            p,
        ),
        EditorControl::Value => input(
            frame,
            rows[1],
            "Field value",
            &editor.value,
            true,
            editor.masked(),
            editor.multiline(),
            p,
        ),
        control => {
            let description = match control {
                EditorControl::Kind => format!(
                    "‹ {} ›\nLeft / Right changes the type.",
                    editor
                        .record
                        .fields
                        .get(editor.field)
                        .map_or("No field", |f| f.kind.label())
                ),
                EditorControl::Secret => format!(
                    "{}\nSpace toggles visibility.",
                    if editor.masked() {
                        "[x] Secret / hidden"
                    } else {
                        "[ ] Visible text"
                    }
                ),
                EditorControl::Generate => {
                    "Generate a 24-character secret.\nReplaces this field's current value.".into()
                }
                EditorControl::Add => "Add a new custom text field.".into(),
                EditorControl::Remove => "Remove the selected field from this draft.".into(),
                EditorControl::MoveUp | EditorControl::MoveDown => {
                    "Reorder the selected field.".into()
                }
                EditorControl::Save => "Save this record to the encrypted vault.".into(),
                EditorControl::Cancel => "Discard this draft without saving.".into(),
                _ => String::new(),
            };
            frame.render_widget(
                Paragraph::new(description)
                    .wrap(Wrap { trim: false })
                    .block(panel(control_label(control), true, p)),
                rows[1],
            );
        }
    }
    frame.render_widget(
        Paragraph::new(
            "Tab / Shift-Tab cycles all 13 controls.\nEnter activates buttons · Ctrl-S saves.",
        )
        .style(style(p.subtext0)),
        rows[2],
    );
}

/// Secret input uses a constant mask and constant cursor; neither reflects length.
#[allow(clippy::too_many_arguments)]
fn input(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    input: &TextInput,
    focused: bool,
    secret: bool,
    multiline: bool,
    p: Palette,
) {
    let block = panel(title, focused, p);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.is_empty() {
        return;
    }
    if secret {
        frame.render_widget(Paragraph::new(MASK).style(style(p.peach)), inner);
        if focused {
            cursor(
                frame,
                inner,
                MASK.len().min(inner.width.saturating_sub(1) as usize),
                0,
            );
        }
        return;
    }
    // The byte cursor can be supplied by callers; clamp to a UTF-8 boundary defensively.
    let mut byte = input.cursor.min(input.value.len());
    while !input.value.is_char_boundary(byte) {
        byte = byte.saturating_sub(1);
    }
    let before = &input.value[..byte];
    let row = if multiline {
        before.bytes().filter(|b| *b == b'\n').count()
    } else {
        0
    };
    let prefix = if multiline {
        before.rsplit('\n').next().unwrap_or("")
    } else {
        before
    };
    let column = display_width(&safe_text(prefix));
    let first_row = row.saturating_sub(inner.height.saturating_sub(1) as usize);
    let left = column.saturating_sub(inner.width.saturating_sub(1) as usize);
    let raw_lines: Vec<&str> = if multiline {
        input.value.split('\n').collect()
    } else {
        vec![&input.value]
    };
    let visible: Vec<Line> = raw_lines
        .into_iter()
        .skip(first_row)
        .take(inner.height as usize)
        .map(|line| Line::from(window(&safe_text(line), left, inner.width as usize)))
        .collect();
    frame.render_widget(Paragraph::new(visible).style(style(p.text)), inner);
    if focused {
        cursor(
            frame,
            inner,
            column.saturating_sub(left),
            row.saturating_sub(first_row),
        );
    }
}

fn display_width(text: &str) -> usize {
    text.chars().map(|c| c.width().unwrap_or(0)).sum()
}

fn window(text: &str, left: usize, width: usize) -> String {
    let mut output = String::new();
    let mut pos = 0;
    let mut used = 0;
    for c in text.chars() {
        let w = c.width().unwrap_or(0);
        if pos >= left {
            if used + w > width {
                break;
            }
            output.push(c);
            used += w;
        } else if pos + w > left {
            // Keep a clipped double-width glyph from shifting the cursor left.
            output.push(' ');
            used += 1;
        }
        pos += w;
    }
    output
}

fn cursor(frame: &mut Frame, area: Rect, x: usize, y: usize) {
    if !area.is_empty() {
        let x = area.x + x.min(area.width.saturating_sub(1) as usize) as u16;
        let y = area.y + y.min(area.height.saturating_sub(1) as usize) as u16;
        let bounds = frame.area();
        if x < bounds.right() && y < bounds.bottom() {
            frame.set_cursor_position((x, y));
        }
    }
}

fn modal(frame: &mut Frame, area: Rect, app: &App, p: Palette) {
    let height = match app.mode {
        Mode::Help => 26,
        Mode::Delete => 10,
        _ => 13,
    };
    let popup = centered(
        inset(area, 1, 0),
        if app.mode == Mode::Help { 76 } else { 60 },
        height,
    );
    frame.render_widget(Clear, popup);
    let title = match app.mode {
        Mode::Templates => "Make room for something new",
        Mode::Delete => "Delete this record?",
        Mode::Help => "A field guide to SimpleCrypt",
        _ => "A softer shade of quiet",
    };
    let block = panel(title, true, p);
    let inner = inset(block.inner(popup), 1, 0);
    frame.render_widget(block, popup);
    match app.mode {
        Mode::Templates => {
            let items: Vec<ListItem> = Template::ALL
                .iter()
                .map(|template| ListItem::new(template.label()))
                .collect();
            let mut state = ListState::default()
                .with_selected(Some(app.template_index.min(Template::ALL.len() - 1)));
            frame.render_stateful_widget(
                List::new(items)
                    .highlight_symbol("› ")
                    .highlight_style(style(p.lavender).bg(p.surface0)),
                inner,
                &mut state,
            );
        }
        Mode::Themes => {
            let items: Vec<ListItem> = Theme::ALL
                .iter()
                .map(|theme| {
                    let swatch = theme.palette();
                    ListItem::new(Line::from(vec![
                        Span::styled(format!("{:<13}", theme.label()), style(p.text)),
                        Span::styled(" ██", style(swatch.mauve)),
                        Span::styled(" ██", style(swatch.peach)),
                        Span::styled(" ██", style(swatch.green)),
                        Span::styled(" ██", style(swatch.blue)),
                        Span::styled(
                            if *theme == app.theme { "  current" } else { "" },
                            style(p.subtext0),
                        ),
                    ]))
                })
                .collect();
            let mut state =
                ListState::default().with_selected(Some(app.theme_index.min(Theme::ALL.len() - 1)));
            frame.render_stateful_widget(
                List::new(items)
                    .highlight_symbol("› ")
                    .highlight_style(style(p.lavender).bg(p.surface0)),
                inner,
                &mut state,
            );
        }
        Mode::Delete => {
            let label = app
                .current_record()
                .map_or_else(|| "this record".into(), |r| safe_text(&r.label));
            frame.render_widget(
                Paragraph::new(vec![
                    Line::styled(label, style(p.peach).add_modifier(Modifier::BOLD)),
                    Line::from(""),
                    Line::from("This removes the record and all its fields."),
                    Line::styled("The change is saved immediately. No undo.", style(p.red)),
                    Line::from(""),
                    Line::styled("y delete     n / Esc keep it", style(p.lavender)),
                ])
                .wrap(Wrap { trim: false }),
                inner,
            );
        }
        Mode::Help => {
            let lines = [
                ("MOVE & FIND", true),
                (
                    "j/k or ↑/↓  select record / field    h/l or Tab  switch panes",
                    false,
                ),
                (
                    "/  search labels    Enter apply    Esc restore / clear filter",
                    false,
                ),
                (
                    "PgUp/PgDn  scroll field text    Home  return to its beginning",
                    false,
                ),
                ("", false),
                ("MAKE IT YOURS", true),
                (
                    "a  add from template    e  edit    d  delete with confirmation",
                    false,
                ),
                (
                    "Editor: Tab / Shift-Tab follows every input and action.",
                    false,
                ),
                (
                    "Enter / Space activates buttons; ←/→ changes field type.",
                    false,
                ),
                (
                    "Text: arrows navigate; Home/End; Ctrl-A/E start/end; Ctrl-U clear.",
                    false,
                ),
                (
                    "Multiline values: Enter inserts newline; ↑/↓ moves between lines.",
                    false,
                ),
                (
                    "Ctrl-S saves the draft. Esc discards it. Secret inputs stay masked.",
                    false,
                ),
                ("", false),
                ("KEEP IT QUIET", true),
                (
                    "r  reveal selected secret for 10s; press again to hide",
                    false,
                ),
                (
                    "L  lock    q  quit    Ctrl-Q / Ctrl-C quit from any screen",
                    false,
                ),
                (
                    "Idle lock discards unsaved drafts. No password recovery.",
                    false,
                ),
                (
                    "Local encrypted storage; labels and fields are encrypted at rest.",
                    false,
                ),
                (
                    "No clipboard integration. A revealed secret can be captured.",
                    false,
                ),
                (
                    "Screen clearing and memory cleanup are best effort, not guarantees.",
                    false,
                ),
                ("", false),
                (
                    "t  Catppuccin theme    ? / Esc / Enter  close this guide",
                    true,
                ),
            ];
            if inner.height < lines.len() as u16 {
                frame.render_widget(Paragraph::new("j/k move · h/l panes · / search\na add · e edit · d delete · r reveal 10s\nPgUp/PgDn scroll · Home top\nEditor: Tab focus · Ctrl-S save · Esc cancel\nL lock · Ctrl-Q quit · t theme\nIdle lock discards drafts. No recovery.\nSecret inputs stay masked. Reveals can be captured.\nEnlarge the terminal for the full guide.\nEsc / Enter closes help.")
                    .wrap(Wrap { trim: false }).style(style(p.subtext1)), inner);
            } else {
                frame.render_widget(
                    Paragraph::new(
                        lines
                            .into_iter()
                            .map(|(text, accent)| {
                                Line::styled(text, style(if accent { p.mauve } else { p.subtext1 }))
                            })
                            .collect::<Vec<_>>(),
                    ),
                    inner,
                );
            }
        }
        _ => {}
    }
}
