use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use zeroize::Zeroizing;

use crate::{
    crypto::Session,
    editor::{Editor, EditorControl, LABEL_LIMIT, PASSWORD_LIMIT, TextInput},
    model::{Field, Record, Template, Vault, generate_password},
    storage::VaultFile,
    theme::Theme,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Create,
    Locked,
    Browse,
    Search,
    Edit,
    Templates,
    Delete,
    Help,
    Themes,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pane {
    Records,
    Fields,
}

pub struct App {
    pub file: VaultFile,
    pub session: Option<Session>,
    pub mode: Mode,
    pub pane: Pane,
    pub theme: Theme,
    pub selected: usize,
    pub selected_field: usize,
    pub detail_scroll: usize,
    pub query: TextInput,
    previous_query: Zeroizing<String>,
    previous_selection: usize,
    pub master: TextInput,
    pub confirmation: TextInput,
    pub auth_focus: usize,
    pub editor: Option<Editor>,
    pub template_index: usize,
    pub theme_index: usize,
    pub status: String,
    pub is_error: bool,
    pub should_quit: bool,
    pub clear_terminal: bool,
    pub write_blocked: bool,
    pub idle_timeout: Duration,
    last_activity: Instant,
    revealed_until: Option<Instant>,
}

impl App {
    pub fn new(file: VaultFile, theme: Theme, idle_timeout: Duration) -> Result<Self> {
        let exists = file.exists()?;
        Ok(Self {
            file,
            session: None,
            mode: if exists { Mode::Locked } else { Mode::Create },
            pane: Pane::Records,
            theme,
            selected: 0,
            selected_field: 0,
            detail_scroll: 0,
            query: TextInput::default(),
            previous_query: Zeroizing::new(String::new()),
            previous_selection: 0,
            master: TextInput::default(),
            confirmation: TextInput::default(),
            auth_focus: 0,
            editor: None,
            template_index: 0,
            theme_index: 0,
            status: if exists {
                "Your vault is locked. Welcome back."
            } else {
                "Create a master password of at least 12 characters. There is no password recovery."
            }
            .into(),
            is_error: false,
            should_quit: false,
            clear_terminal: false,
            write_blocked: false,
            idle_timeout,
            last_activity: Instant::now(),
            revealed_until: None,
        })
    }

    pub fn records(&self) -> &[Record] {
        self.session
            .as_ref()
            .map_or(&[], |s| s.data.records.as_slice())
    }

    pub fn filtered_indices(&self) -> Vec<usize> {
        let query = Zeroizing::new(self.query.value.to_lowercase());
        self.records()
            .iter()
            .enumerate()
            .filter_map(|(index, record)| {
                let label = Zeroizing::new(record.label.to_lowercase());
                label.contains(query.as_str()).then_some(index)
            })
            .collect()
    }

    pub fn current_record(&self) -> Option<&Record> {
        self.filtered_indices()
            .get(self.selected)
            .and_then(|i| self.records().get(*i))
    }

    pub fn current_field(&self) -> Option<&Field> {
        self.current_record()
            .and_then(|r| r.fields.get(self.selected_field))
    }

    pub fn revealed(&self) -> bool {
        self.revealed_until.is_some()
    }

    pub fn idle_remaining(&self, now: Instant) -> Duration {
        self.idle_timeout
            .saturating_sub(now.saturating_duration_since(self.last_activity))
    }

    pub fn message(&mut self, message: impl Into<String>, error: bool) {
        self.status = message.into();
        self.is_error = error;
    }

    pub fn lock(&mut self, automatic: bool) {
        let had_draft = self.editor.is_some();
        self.session = None;
        self.editor = None;
        self.master.clear();
        self.confirmation.clear();
        self.query.clear();
        self.previous_query = Zeroizing::new(String::new());
        self.selected = 0;
        self.selected_field = 0;
        self.detail_scroll = 0;
        self.revealed_until = None;
        self.auth_focus = 0;
        self.mode = Mode::Locked;
        self.clear_terminal = true;
        self.message(
            if had_draft {
                "Vault locked. The unsaved editor draft was discarded."
            } else if automatic {
                "Locked after inactivity. Your saved records are safe."
            } else {
                "Vault locked. Small vault. Quiet secrets."
            },
            false,
        );
    }

    pub fn tick(&mut self, now: Instant) {
        if self.revealed_until.is_some_and(|until| now >= until) {
            self.revealed_until = None;
            self.clear_terminal = true;
        }
        if self.session.is_some()
            && now.saturating_duration_since(self.last_activity) >= self.idle_timeout
        {
            self.lock(true);
        }
    }

    pub fn event(&mut self, event: Event, now: Instant) {
        self.tick(now);
        match event {
            Event::Key(key) if key.kind != KeyEventKind::Release => {
                self.last_activity = now;
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('q'))
                {
                    self.lock(false);
                    self.should_quit = true;
                    return;
                }
                self.key(key, now);
            }
            Event::Paste(text) => {
                self.last_activity = now;
                let text = Zeroizing::new(text);
                let accepted = match self.mode {
                    Mode::Create | Mode::Locked => {
                        let input = if self.auth_focus == 0 {
                            &mut self.master
                        } else {
                            &mut self.confirmation
                        };
                        input.insert(&text, false, PASSWORD_LIMIT)
                    }
                    Mode::Search => {
                        self.selected = 0;
                        self.query.insert(&text, false, LABEL_LIMIT)
                    }
                    Mode::Edit => self.editor.as_mut().is_some_and(|e| e.paste(&text)),
                    _ => false,
                };
                if !accepted {
                    self.message("Paste rejected: select a text input, respect its size limit, and omit control characters.", true);
                }
            }
            Event::FocusLost => {
                self.revealed_until = None;
                self.clear_terminal = true;
            }
            _ => {}
        }
    }

    fn key(&mut self, key: KeyEvent, now: Instant) {
        match self.mode {
            Mode::Create | Mode::Locked => self.auth_key(key),
            Mode::Browse => self.browse_key(key, now),
            Mode::Search => match key.code {
                KeyCode::Esc => {
                    self.query = TextInput::new(&self.previous_query);
                    self.selected = self.previous_selection;
                    self.previous_query = Zeroizing::new(String::new());
                    self.mode = Mode::Browse;
                    self.clamp_selection();
                }
                KeyCode::Enter => {
                    self.previous_query = Zeroizing::new(String::new());
                    self.mode = Mode::Browse;
                    self.message(
                        "Filter applied. Press / to change it, or Esc to clear it.",
                        false,
                    );
                }
                _ => {
                    self.query.key(key, false, LABEL_LIMIT);
                    self.selected = 0;
                    self.selected_field = 0;
                    self.detail_scroll = 0;
                }
            },
            Mode::Edit => self.editor_key(key),
            Mode::Templates => match key.code {
                KeyCode::Esc => self.mode = Mode::Browse,
                KeyCode::Char('j') | KeyCode::Down => {
                    self.template_index = (self.template_index + 1) % Template::ALL.len()
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    self.template_index =
                        (self.template_index + Template::ALL.len() - 1) % Template::ALL.len()
                }
                KeyCode::Enter => match Template::ALL[self.template_index].make_record() {
                    Ok(record) => {
                        self.editor = Some(Editor::new(record, false));
                        self.mode = Mode::Edit;
                        self.message(
                            "Ctrl-S saves. Esc cancels. Unsaved drafts are discarded on lock.",
                            false,
                        );
                    }
                    Err(error) => self.message(error.to_string(), true),
                },
                KeyCode::Char('L') => self.lock(false),
                _ => {}
            },
            Mode::Delete => match key.code {
                KeyCode::Char('y') => self.delete_record(),
                KeyCode::Char('n') | KeyCode::Esc => self.mode = Mode::Browse,
                KeyCode::Char('L') => self.lock(false),
                _ => {}
            },
            Mode::Help => match key.code {
                KeyCode::Char('L') => self.lock(false),
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Enter | KeyCode::Char('q') => {
                    self.mode = Mode::Browse
                }
                _ => {}
            },
            Mode::Themes => match key.code {
                KeyCode::Esc => self.mode = Mode::Browse,
                KeyCode::Char('j') | KeyCode::Down => {
                    self.theme_index = (self.theme_index + 1) % Theme::ALL.len()
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    self.theme_index = (self.theme_index + Theme::ALL.len() - 1) % Theme::ALL.len()
                }
                KeyCode::Enter => {
                    self.theme = Theme::ALL[self.theme_index];
                    self.mode = Mode::Browse;
                    self.message(
                        "Theme changed for this session. Use --theme to choose a launch theme.",
                        false,
                    );
                }
                KeyCode::Char('L') => self.lock(false),
                _ => {}
            },
        }
    }

    fn auth_key(&mut self, key: KeyEvent) {
        if self.write_blocked {
            self.message("Save durability is uncertain. Quit with Ctrl-Q and reopen the vault before continuing.", true);
            return;
        }
        match key.code {
            KeyCode::Tab | KeyCode::BackTab if self.mode == Mode::Create => {
                self.auth_focus = 1 - self.auth_focus
            }
            KeyCode::Enter if self.mode == Mode::Create && self.auth_focus == 0 => {
                self.auth_focus = 1
            }
            KeyCode::Enter => self.authenticate(),
            KeyCode::Esc => {
                self.master.clear();
                self.confirmation.clear();
                self.auth_focus = 0;
            }
            _ => {
                let input = if self.auth_focus == 0 {
                    &mut self.master
                } else {
                    &mut self.confirmation
                };
                input.key(key, false, PASSWORD_LIMIT);
            }
        }
    }

    fn authenticate(&mut self) {
        if self.mode == Mode::Create {
            if self.master.value.chars().count() < 12 {
                self.message("Use a master password with at least 12 characters; a long unique passphrase is best.", true);
                self.auth_focus = 0;
                return;
            }
            if self.master.value.as_str() != self.confirmation.value.as_str() {
                self.confirmation.clear();
                self.message(
                    "Master passwords do not match. Re-enter the confirmation.",
                    true,
                );
                return;
            }
            let result = Session::create(&self.master.value);
            self.master.clear();
            self.confirmation.clear();
            self.auth_focus = 0;
            match result {
                Ok(session) => match session.seal(&session.data) {
                    Ok(bytes) => match self.file.save(&bytes, true) {
                        Ok(()) => {
                            self.session = Some(session);
                            self.unlocked("Vault created. Press a to add your first record.");
                        }
                        Err(error) => {
                            if error.committed() {
                                self.write_blocked = true;
                                self.mode = Mode::Locked;
                            }
                            self.message(error.to_string(), true);
                        }
                    },
                    Err(error) => self.message(error.to_string(), true),
                },
                Err(error) => self.message(error.to_string(), true),
            }
        } else {
            let result = self
                .file
                .read()
                .and_then(|bytes| Session::unlock(&bytes, &self.master.value));
            self.master.clear();
            match result {
                Ok(session) => {
                    self.session = Some(session);
                    self.unlocked("Vault unlocked. / searches labels · ? opens help.");
                }
                Err(error) => self.message(error.to_string(), true),
            }
        }
    }

    fn unlocked(&mut self, message: &str) {
        self.mode = Mode::Browse;
        self.last_activity = Instant::now();
        self.clear_terminal = true;
        self.message(message, false);
    }

    fn browse_key(&mut self, key: KeyEvent, now: Instant) {
        match key.code {
            KeyCode::PageDown => {
                self.detail_scroll = self.detail_scroll.saturating_add(5).min(u16::MAX as usize)
            }
            KeyCode::PageUp => self.detail_scroll = self.detail_scroll.saturating_sub(5),
            KeyCode::Home => self.detail_scroll = 0,
            KeyCode::Char('j') | KeyCode::Down => self.navigate(1),
            KeyCode::Char('k') | KeyCode::Up => self.navigate(-1),
            KeyCode::Char('h') | KeyCode::Left => {
                self.pane = Pane::Records;
                self.revealed_until = None;
            }
            KeyCode::Char('l') | KeyCode::Right | KeyCode::Enter => {
                self.pane = Pane::Fields;
                self.revealed_until = None;
            }
            KeyCode::Tab | KeyCode::BackTab => {
                self.pane = if self.pane == Pane::Records {
                    Pane::Fields
                } else {
                    Pane::Records
                };
                self.revealed_until = None;
            }
            KeyCode::Char('/') => {
                self.previous_query = Zeroizing::new(self.query.value.to_string());
                self.previous_selection = self.selected;
                self.revealed_until = None;
                self.mode = Mode::Search;
            }
            KeyCode::Esc => {
                self.query.clear();
                self.selected = 0;
                self.selected_field = 0;
                self.revealed_until = None;
            }
            KeyCode::Char('a') => {
                self.mode = Mode::Templates;
                self.template_index = 0;
                self.revealed_until = None;
            }
            KeyCode::Char('e') => {
                if let Some(record) = self.current_record() {
                    self.editor = Some(Editor::new(record.clone(), true));
                    self.mode = Mode::Edit;
                    self.revealed_until = None;
                    self.message(
                        "Ctrl-S saves. Esc cancels. Unsaved drafts are discarded on lock.",
                        false,
                    );
                }
            }
            KeyCode::Char('d') if self.current_record().is_some() => {
                self.mode = Mode::Delete;
                self.revealed_until = None;
            }
            KeyCode::Char('r') if self.current_field().is_some_and(|f| f.secret) => {
                self.revealed_until = if self.revealed_until.is_some() {
                    None
                } else {
                    Some(now + Duration::from_secs(10))
                };
            }
            KeyCode::Char('L') => self.lock(false),
            KeyCode::Char('?') => {
                self.mode = Mode::Help;
                self.revealed_until = None;
            }
            KeyCode::Char('t') => {
                self.mode = Mode::Themes;
                self.revealed_until = None;
                self.theme_index = Theme::ALL
                    .iter()
                    .position(|theme| *theme == self.theme)
                    .unwrap_or(0);
            }
            KeyCode::Char('q') => {
                self.lock(false);
                self.should_quit = true;
            }
            _ => {}
        }
    }

    fn navigate(&mut self, direction: isize) {
        self.revealed_until = None;
        self.detail_scroll = 0;
        match self.pane {
            Pane::Records => {
                let count = self.filtered_indices().len();
                self.selected = (self.selected as isize + direction)
                    .clamp(0, count.saturating_sub(1) as isize)
                    as usize;
                self.selected_field = 0;
                self.detail_scroll = 0;
            }
            Pane::Fields => {
                let count = self.current_record().map_or(0, |r| r.fields.len());
                self.selected_field = (self.selected_field as isize + direction)
                    .clamp(0, count.saturating_sub(1) as isize)
                    as usize;
            }
        }
    }

    fn clamp_selection(&mut self) {
        self.selected = self
            .selected
            .min(self.filtered_indices().len().saturating_sub(1));
        self.selected_field = self.selected_field.min(
            self.current_record()
                .map_or(0, |r| r.fields.len())
                .saturating_sub(1),
        );
    }

    fn editor_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
            self.save_editor();
            return;
        }
        if key.code == KeyCode::Esc {
            self.editor = None;
            self.mode = Mode::Browse;
            self.message("Editor cancelled. No changes saved.", false);
            return;
        }
        let Some(editor) = self.editor.as_mut() else {
            self.mode = Mode::Browse;
            return;
        };
        if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
            editor.tab(key.code == KeyCode::BackTab || key.modifiers.contains(KeyModifiers::SHIFT));
            return;
        }
        let mut save = false;
        let mut cancel = false;
        match editor.focus {
            EditorControl::FieldList => match key.code {
                KeyCode::Char('j') | KeyCode::Down => editor.select_field(1),
                KeyCode::Char('k') | KeyCode::Up => editor.select_field(-1),
                KeyCode::Enter => editor.focus = EditorControl::Name,
                _ => {}
            },
            EditorControl::Kind => match key.code {
                KeyCode::Right | KeyCode::Char('l') | KeyCode::Enter | KeyCode::Char(' ') => {
                    editor.cycle_kind(1)
                }
                KeyCode::Left | KeyCode::Char('h') => editor.cycle_kind(-1),
                _ => {}
            },
            EditorControl::Secret if matches!(key.code, KeyCode::Enter | KeyCode::Char(' ')) => {
                editor.toggle_secret()
            }
            control
                if matches!(key.code, KeyCode::Enter | KeyCode::Char(' '))
                    && !matches!(
                        control,
                        EditorControl::Label
                            | EditorControl::Name
                            | EditorControl::Value
                            | EditorControl::Secret
                    ) =>
            {
                match control {
                    EditorControl::Generate if !editor.record.fields.is_empty() => {
                        match generate_password(24) {
                            Ok(password) => {
                                editor.value = TextInput::new(&password);
                                if let Some(field) = editor.record.fields.get_mut(editor.field) {
                                    field.secret = true;
                                }
                                self.message("Generated a 24-character random secret. Ctrl-S saves the record.", false);
                            }
                            Err(error) => self.message(error.to_string(), true),
                        }
                    }
                    EditorControl::Add => editor.add_field(),
                    EditorControl::Remove => editor.remove_field(),
                    EditorControl::MoveUp => editor.move_field(-1),
                    EditorControl::MoveDown => editor.move_field(1),
                    EditorControl::Save => save = true,
                    EditorControl::Cancel => cancel = true,
                    _ => {}
                }
            }
            _ => {
                editor.text_key(key);
            }
        }
        if save {
            self.save_editor();
        }
        if cancel {
            self.editor = None;
            self.mode = Mode::Browse;
            self.message("Editor cancelled. No changes saved.", false);
        }
    }

    fn persist(&mut self, data: Vault) -> bool {
        if self.write_blocked {
            self.message("Reopen the vault before attempting another write.", true);
            return false;
        }
        let Some(session) = self.session.as_ref() else {
            return false;
        };
        let bytes = match session.seal(&data) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.message(error.to_string(), true);
                return false;
            }
        };
        match self.file.save(&bytes, false) {
            Ok(()) => {
                if let Some(session) = self.session.as_mut() {
                    session.data = data;
                }
                true
            }
            Err(error) => {
                if error.committed() {
                    self.write_blocked = true;
                    self.lock(false);
                }
                self.message(error.to_string(), true);
                false
            }
        }
    }

    fn save_editor(&mut self) {
        let Some(editor) = self.editor.as_mut() else {
            return;
        };
        editor.sync();
        let id = editor.record.id.clone();
        let Some(session) = self.session.as_ref() else {
            return;
        };
        let mut data = session.data.clone();
        if editor.existing {
            let Some(index) = data.records.iter().position(|r| r.id == id) else {
                self.message("The edited record is no longer available.", true);
                return;
            };
            data.records[index] = editor.record.clone();
        } else {
            data.records.push(editor.record.clone());
        }
        if self.persist(data) {
            self.editor = None;
            self.mode = Mode::Browse;
            self.query.clear();
            self.selected = self.records().iter().position(|r| r.id == id).unwrap_or(0);
            self.selected_field = 0;
            self.detail_scroll = 0;
            self.message("Record saved. Your vault is encrypted on disk.", false);
        }
    }

    fn delete_record(&mut self) {
        let Some(index) = self.filtered_indices().get(self.selected).copied() else {
            self.mode = Mode::Browse;
            return;
        };
        let Some(session) = self.session.as_ref() else {
            return;
        };
        let mut data = session.data.clone();
        data.records.remove(index);
        if self.persist(data) {
            self.mode = Mode::Browse;
            self.clamp_selection();
            self.message("Record deleted and encrypted vault saved.", false);
        }
    }
}
