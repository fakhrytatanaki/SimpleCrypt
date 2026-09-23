use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use zeroize::Zeroizing;

use crate::model::{Field, FieldKind, MAX_FIELDS_PER_RECORD, Record};
pub use crate::model::{
    MAX_FIELD_NAME_LEN as NAME_LIMIT, MAX_FIELD_VALUE_LEN as INPUT_LIMIT,
    MAX_LABEL_LEN as LABEL_LIMIT,
};
pub const PASSWORD_LIMIT: usize = 1024;

#[derive(Default)]
pub struct TextInput {
    pub value: Zeroizing<String>,
    /// A byte offset, always on a UTF-8 character boundary.
    pub cursor: usize,
}

impl TextInput {
    pub fn new(value: &str) -> Self {
        Self {
            value: Zeroizing::new(value.to_owned()),
            cursor: value.len(),
        }
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }

    pub fn insert(&mut self, text: &str, multiline: bool, limit: usize) -> bool {
        if self.value.len().saturating_add(text.len()) > limit
            || text
                .chars()
                .any(|c| c.is_control() && !(multiline && c == '\n'))
        {
            return false;
        }
        self.value.insert_str(self.cursor, text);
        self.cursor += text.len();
        true
    }

    pub fn key(&mut self, key: KeyEvent, multiline: bool, limit: usize) -> bool {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            match key.code {
                KeyCode::Char('a') => self.cursor = 0,
                KeyCode::Char('e') => self.cursor = self.value.len(),
                KeyCode::Char('u') => self.clear(),
                _ => return false,
            }
            return true;
        }
        if key.modifiers.contains(KeyModifiers::ALT) {
            return false;
        }
        match key.code {
            KeyCode::Char(c) => {
                let mut bytes = [0u8; 4];
                return self.insert(c.encode_utf8(&mut bytes), multiline, limit);
            }
            KeyCode::Enter if multiline => return self.insert("\n", true, limit),
            KeyCode::Left => self.cursor = self.previous(),
            KeyCode::Right => self.cursor = self.next(),
            KeyCode::Up if multiline => self.move_vertical(-1),
            KeyCode::Down if multiline => self.move_vertical(1),
            KeyCode::Home => self.cursor = if multiline { self.line_start() } else { 0 },
            KeyCode::End => {
                self.cursor = if multiline {
                    self.line_end()
                } else {
                    self.value.len()
                }
            }
            KeyCode::Backspace if self.cursor > 0 => {
                let start = self.previous();
                self.value.drain(start..self.cursor);
                self.cursor = start;
            }
            KeyCode::Delete if self.cursor < self.value.len() => {
                let next = self.next();
                self.value.drain(self.cursor..next);
            }
            _ => return false,
        }
        true
    }

    fn line_start(&self) -> usize {
        self.value[..self.cursor].rfind('\n').map_or(0, |i| i + 1)
    }

    fn line_end(&self) -> usize {
        self.value[self.cursor..]
            .find('\n')
            .map_or(self.value.len(), |i| self.cursor + i)
    }

    fn move_vertical(&mut self, direction: isize) {
        let start = self.line_start();
        let end = self.line_end();
        let column = self.value[start..self.cursor].chars().count();
        let (target_start, target_end) = if direction < 0 && start > 0 {
            (
                self.value[..start - 1].rfind('\n').map_or(0, |i| i + 1),
                start - 1,
            )
        } else if direction > 0 && end < self.value.len() {
            let next = end + 1;
            (
                next,
                self.value[next..]
                    .find('\n')
                    .map_or(self.value.len(), |i| next + i),
            )
        } else {
            return;
        };
        self.cursor = self.value[target_start..target_end]
            .char_indices()
            .nth(column)
            .map_or(target_end, |(i, _)| target_start + i);
    }

    fn previous(&self) -> usize {
        self.value[..self.cursor]
            .char_indices()
            .next_back()
            .map_or(0, |(i, _)| i)
    }

    fn next(&self) -> usize {
        self.value[self.cursor..]
            .chars()
            .next()
            .map_or(self.cursor, |c| self.cursor + c.len_utf8())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EditorControl {
    Label,
    FieldList,
    Name,
    Kind,
    Secret,
    Value,
    Generate,
    Add,
    Remove,
    MoveUp,
    MoveDown,
    Save,
    Cancel,
}

impl EditorControl {
    pub const ALL: [Self; 13] = [
        Self::Label,
        Self::FieldList,
        Self::Name,
        Self::Kind,
        Self::Secret,
        Self::Value,
        Self::Generate,
        Self::Add,
        Self::Remove,
        Self::MoveUp,
        Self::MoveDown,
        Self::Save,
        Self::Cancel,
    ];

    fn step(self, direction: isize) -> Self {
        let i = Self::ALL.iter().position(|c| *c == self).unwrap_or(0);
        Self::ALL[(i as isize + direction).rem_euclid(Self::ALL.len() as isize) as usize]
    }
}

pub struct Editor {
    pub record: Record,
    pub label: TextInput,
    pub name: TextInput,
    pub value: TextInput,
    pub field: usize,
    pub focus: EditorControl,
    pub existing: bool,
}

impl Editor {
    pub fn new(record: Record, existing: bool) -> Self {
        let label = TextInput::new(&record.label);
        let mut editor = Self {
            record,
            label,
            name: TextInput::default(),
            value: TextInput::default(),
            field: 0,
            focus: EditorControl::Label,
            existing,
        };
        editor.load_field();
        editor
    }

    pub fn sync(&mut self) {
        drop(Zeroizing::new(std::mem::replace(
            &mut self.record.label,
            self.label.value.to_string(),
        )));
        if let Some(field) = self.record.fields.get_mut(self.field) {
            // Drop the previous allocations through zeroizing owners.
            let old_name = std::mem::replace(&mut field.name, self.name.value.to_string());
            let old_value = std::mem::replace(&mut field.value, self.value.value.to_string());
            drop(Zeroizing::new(old_name));
            drop(Zeroizing::new(old_value));
        }
    }

    fn load_field(&mut self) {
        if let Some(field) = self.record.fields.get(self.field) {
            self.name = TextInput::new(&field.name);
            self.value = TextInput::new(&field.value);
        } else {
            self.name.clear();
            self.value.clear();
        }
    }

    pub fn select_field(&mut self, direction: isize) {
        self.sync();
        if !self.record.fields.is_empty() {
            self.field = (self.field as isize + direction)
                .clamp(0, self.record.fields.len() as isize - 1) as usize;
        }
        self.load_field();
    }

    pub fn tab(&mut self, reverse: bool) {
        self.sync();
        self.focus = self.focus.step(if reverse { -1 } else { 1 });
    }

    pub fn multiline(&self) -> bool {
        self.record
            .fields
            .get(self.field)
            .is_some_and(|f| f.kind == FieldKind::Multiline)
    }

    pub fn masked(&self) -> bool {
        self.record.fields.get(self.field).is_some_and(|f| f.secret)
    }

    pub fn text_key(&mut self, key: KeyEvent) -> bool {
        let multiline = self.multiline();
        match self.focus {
            EditorControl::Label => self.label.key(key, false, LABEL_LIMIT),
            EditorControl::Name => self.name.key(key, false, NAME_LIMIT),
            EditorControl::Value => self.value.key(key, multiline, INPUT_LIMIT),
            _ => false,
        }
    }

    pub fn paste(&mut self, text: &str) -> bool {
        let multiline = self.multiline();
        match self.focus {
            EditorControl::Label => self.label.insert(text, false, LABEL_LIMIT),
            EditorControl::Name => self.name.insert(text, false, NAME_LIMIT),
            EditorControl::Value => self.value.insert(text, multiline, INPUT_LIMIT),
            _ => false,
        }
    }

    pub fn add_field(&mut self) {
        self.sync();
        if self.record.fields.len() < MAX_FIELDS_PER_RECORD {
            self.record
                .fields
                .push(Field::new("custom", FieldKind::Text));
            self.field = self.record.fields.len() - 1;
            self.load_field();
            self.focus = EditorControl::Name;
        }
    }

    pub fn remove_field(&mut self) {
        self.sync();
        if self.field < self.record.fields.len() {
            self.record.fields.remove(self.field);
            self.field = self.field.min(self.record.fields.len().saturating_sub(1));
            self.load_field();
        }
    }

    pub fn move_field(&mut self, direction: isize) {
        self.sync();
        let target = self.field as isize + direction;
        if target >= 0 && (target as usize) < self.record.fields.len() {
            self.record.fields.swap(self.field, target as usize);
            self.field = target as usize;
        }
    }

    pub fn cycle_kind(&mut self, direction: isize) {
        if let Some(field) = self.record.fields.get_mut(self.field) {
            let index = FieldKind::ALL
                .iter()
                .position(|k| *k == field.kind)
                .unwrap_or(0);
            field.kind = FieldKind::ALL
                [(index as isize + direction).rem_euclid(FieldKind::ALL.len() as isize) as usize];
            if field.kind == FieldKind::Password {
                field.secret = true;
            }
        }
    }

    pub fn toggle_secret(&mut self) {
        if let Some(field) = self.record.fields.get_mut(self.field) {
            field.secret = !field.secret;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_boundaries_and_deletion() {
        let mut input = TextInput::new("a猫é");
        input.key(KeyCode::Left.into(), false, 100);
        input.key(KeyCode::Backspace.into(), false, 100);
        assert!(input.value.as_str() == "aé");
        input.key(KeyCode::Delete.into(), false, 100);
        assert!(input.value.as_str() == "a");
    }

    #[test]
    fn literal_navigation_keys_and_bounded_paste() {
        let mut input = TextInput::default();
        for c in "hjkl/q".chars() {
            input.key(KeyCode::Char(c).into(), false, 16);
        }
        assert!(input.value.as_str() == "hjkl/q");
        assert!(!input.insert("\x1b[31m", false, 100));
        assert!(!input.insert("too long", false, 7));
        assert!(!input.insert("\n", false, 16));
        assert!(input.insert("\n", true, 16));
    }
}
