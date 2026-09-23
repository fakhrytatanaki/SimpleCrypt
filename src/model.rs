//! Ordered vault records. All owned plaintext strings are zeroized on drop.
use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Text limits are in UTF-8 bytes, not Unicode scalar values.
pub const MAX_LABEL_LEN: usize = 256;
pub const MAX_FIELD_NAME_LEN: usize = 128;
pub const MAX_FIELD_VALUE_LEN: usize = 64 * 1024;
pub const MAX_NAME_LEN: usize = MAX_FIELD_NAME_LEN;
pub const MAX_VALUE_LEN: usize = MAX_FIELD_VALUE_LEN;
pub const MAX_RECORDS: usize = 10_000;
pub const MAX_FIELDS_PER_RECORD: usize = 128;
pub const MIN_PASSWORD_LENGTH: usize = 12;
pub const MAX_PASSWORD_LENGTH: usize = 1024;
pub const DEFAULT_PASSWORD_LENGTH: usize = 24;

#[derive(Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Vault {
    pub records: Vec<Record>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub id: String,
    pub label: String,
    pub fields: Vec<Field>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub name: String,
    pub value: String,
    #[zeroize(skip)]
    pub kind: FieldKind,
    pub secret: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldKind {
    Text,
    Multiline,
    Email,
    Username,
    Password,
    Address,
}

impl FieldKind {
    pub const ALL: [Self; 6] = [
        Self::Text,
        Self::Multiline,
        Self::Email,
        Self::Username,
        Self::Password,
        Self::Address,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Text => "Text",
            Self::Multiline => "Multiline",
            Self::Email => "Email",
            Self::Username => "Username",
            Self::Password => "Password",
            Self::Address => "Address",
        }
    }
}

impl Field {
    pub fn new(name: &str, kind: FieldKind) -> Self {
        Self {
            name: name.to_owned(),
            value: String::new(),
            kind,
            secret: kind == FieldKind::Password,
        }
    }
}

impl Record {
    pub fn new(label: &str) -> Result<Self> {
        ensure!(
            !label.trim().is_empty() && label.len() <= MAX_LABEL_LEN,
            "Record label must be nonempty and at most {MAX_LABEL_LEN} bytes."
        );
        let mut random = Zeroizing::new([0_u8; 16]);
        getrandom::getrandom(random.as_mut())
            .map_err(|_| anyhow!("Operating-system randomness is unavailable."))?;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut id = String::with_capacity(32);
        for byte in random.iter() {
            id.push(HEX[(byte >> 4) as usize] as char);
            id.push(HEX[(byte & 15) as usize] as char);
        }
        Ok(Self {
            id,
            label: label.to_owned(),
            fields: Vec::new(),
        })
    }
}

impl Vault {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.records.len() <= MAX_RECORDS, "Too many records.");
        let mut ids = HashSet::with_capacity(self.records.len());
        for record in &self.records {
            ensure!(
                record.id.len() == 32
                    && record
                        .id
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
                "Invalid record identifier."
            );
            ensure!(
                ids.insert(record.id.as_str()),
                "Duplicate record identifier."
            );
            ensure!(
                !record.label.trim().is_empty() && record.label.len() <= MAX_LABEL_LEN,
                "Record label must be nonempty and at most {MAX_LABEL_LEN} bytes."
            );
            ensure!(
                record.fields.len() <= MAX_FIELDS_PER_RECORD,
                "Too many fields in a record."
            );
            for field in &record.fields {
                ensure!(
                    !field.name.trim().is_empty() && field.name.len() <= MAX_FIELD_NAME_LEN,
                    "Field name must be nonempty and at most {MAX_FIELD_NAME_LEN} bytes."
                );
                ensure!(
                    field.value.len() <= MAX_FIELD_VALUE_LEN,
                    "Field value is too long."
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Template {
    Login,
    Email,
    Bitcoin,
    SecureNote,
    Blank,
}

impl Template {
    pub const ALL: [Self; 5] = [
        Self::Login,
        Self::Email,
        Self::Bitcoin,
        Self::SecureNote,
        Self::Blank,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Login => "Login",
            Self::Email => "Email",
            Self::Bitcoin => "Bitcoin Address",
            Self::SecureNote => "Secure Note",
            Self::Blank => "Blank",
        }
    }

    pub fn make_record(self) -> Result<Record> {
        let mut record = Record::new(match self {
            Self::Blank => "Untitled",
            _ => self.label(),
        })?;
        record.fields = match self {
            Self::Login => vec![
                Field::new("Username", FieldKind::Username),
                Field::new("Password", FieldKind::Password),
                Field::new("Website", FieldKind::Text),
            ],
            Self::Email => vec![
                Field::new("Email", FieldKind::Email),
                Field::new("Password", FieldKind::Password),
                Field::new("Notes", FieldKind::Multiline),
            ],
            Self::Bitcoin => vec![
                Field::new("Address", FieldKind::Address),
                Field::new("Network", FieldKind::Text),
                Field::new("Notes", FieldKind::Multiline),
            ],
            Self::SecureNote => {
                let mut field = Field::new("Note", FieldKind::Multiline);
                field.secret = true;
                vec![field]
            }
            Self::Blank => Vec::new(),
        };
        Ok(record)
    }
}

/// Uniform sampling with rejection avoids modulo bias. No weak RNG fallback.
pub fn generate_password(length: usize) -> Result<Zeroizing<String>> {
    ensure!(
        (MIN_PASSWORD_LENGTH..=MAX_PASSWORD_LENGTH).contains(&length),
        "Generated password length must be {MIN_PASSWORD_LENGTH}–{MAX_PASSWORD_LENGTH}."
    );
    const ALPHABET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.?";
    let accept_below = (256 / ALPHABET.len()) * ALPHABET.len();
    let mut result = Zeroizing::new(String::with_capacity(length));
    let mut random = Zeroizing::new([0_u8; 128]);
    while result.len() < length {
        getrandom::getrandom(random.as_mut())
            .map_err(|_| anyhow!("Operating-system randomness is unavailable."))?;
        for &byte in random.iter() {
            if (byte as usize) < accept_below {
                result.push(ALPHABET[byte as usize % ALPHABET.len()] as char);
                if result.len() == length {
                    break;
                }
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_and_defaults_are_valid() {
        for template in Template::ALL {
            let record = template.make_record().unwrap();
            assert!(!template.label().is_empty());
            for field in &record.fields {
                if field.kind == FieldKind::Password {
                    assert!(field.secret);
                }
            }
            Vault {
                records: vec![record],
            }
            .validate()
            .unwrap();
        }
        for kind in FieldKind::ALL {
            assert!(!kind.label().is_empty());
            let field = Field::new("Custom", kind);
            assert!(field.value.is_empty());
            assert_eq!(field.secret, kind == FieldKind::Password);
        }
    }

    #[test]
    fn identifiers_are_stable_and_labels_may_repeat() {
        let first = Record::new("duplicate").unwrap();
        let second = Record::new("duplicate").unwrap();
        assert_ne!(first.id, second.id);
        let encoded = Zeroizing::new(serde_json::to_vec(&first).unwrap());
        let decoded: Record = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(first.id, decoded.id);
        Vault {
            records: vec![first.clone(), second],
        }
        .validate()
        .unwrap();
        assert!(
            Vault {
                records: vec![first.clone(), first]
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn validates_utf8_byte_bounds_and_structure() {
        assert!(Record::new("").is_err());
        assert!(Record::new("  ").is_err());
        assert!(Record::new(&"é".repeat(MAX_LABEL_LEN / 2 + 1)).is_err());
        let mut vault = Vault {
            records: vec![Record::new("Unicode 日本語").unwrap()],
        };
        vault.records[0]
            .fields
            .push(Field::new("note", FieldKind::Multiline));
        vault.records[0].fields[0].value = "\n\u{1b}[31m日本語".to_owned();
        vault.validate().unwrap(); // Rendering, not storage, neutralizes controls.
        vault.records[0].fields[0].value = "x".repeat(MAX_FIELD_VALUE_LEN + 1);
        assert!(vault.validate().is_err());
        vault.records[0].fields[0].value.clear();
        vault.records[0].fields[0].name.clear();
        assert!(vault.validate().is_err());
        vault.records[0].fields.clear();
        vault.records[0].id = "invalid".to_owned();
        assert!(vault.validate().is_err());
    }

    #[test]
    fn count_limits_and_unknown_fields_are_rejected() {
        let mut vault = Vault {
            records: vec![Record::new("limit").unwrap()],
        };
        vault.records[0].fields = vec![Field::new("x", FieldKind::Text); MAX_FIELDS_PER_RECORD + 1];
        assert!(vault.validate().is_err());
        vault.records = vec![Record::new("x").unwrap(); MAX_RECORDS + 1];
        assert!(vault.validate().is_err());
        assert!(serde_json::from_str::<Vault>(r#"{"records":[],"unexpected":true}"#).is_err());
    }

    #[test]
    fn generated_passwords_are_bounded_and_random() {
        assert!(generate_password(MIN_PASSWORD_LENGTH - 1).is_err());
        assert!(generate_password(MAX_PASSWORD_LENGTH + 1).is_err());
        for length in [
            MIN_PASSWORD_LENGTH,
            DEFAULT_PASSWORD_LENGTH,
            MAX_PASSWORD_LENGTH,
        ] {
            let a = generate_password(length).unwrap();
            let b = generate_password(length).unwrap();
            assert_eq!(a.len(), length);
            assert!(a.bytes().all(|b| b.is_ascii_graphic()));
            assert!(a.as_str() != b.as_str());
        }
    }

    #[test]
    fn explicit_zeroization_clears_all_plaintext_owners() {
        let mut vault = Vault {
            records: vec![Template::Login.make_record().unwrap()],
        };
        vault.records[0].fields[1].value = "synthetic-secret".to_owned();
        vault.zeroize();
        assert!(vault.records.is_empty());
    }
}
