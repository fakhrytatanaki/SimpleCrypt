//! Versioned, fully authenticated vault envelope. No attacker-selected KDF work.
//!
//! Header (little endian): magic[8], format u16, KDF u8, cipher u8,
//! Argon version u32, memory KiB u32, passes u32, lanes u32, salt[16],
//! nonce[24], ciphertext length u64, reserved[4]. All 80 bytes are AAD.
use crate::model::Vault;
use anyhow::{Result, anyhow, bail, ensure};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305, XNonce};
use std::io::{self, Write};
use zeroize::Zeroizing;

pub const HEADER_SIZE: usize = 80;
pub const MAX_CIPHERTEXT_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_FILE_SIZE: usize = HEADER_SIZE + MAX_CIPHERTEXT_SIZE;
const TAG_SIZE: usize = 16;
const MAGIC: &[u8; 8] = b"SCVAULT\0";
const FORMAT_VERSION: u16 = 1;
const KDF_ID: u8 = 1;
const CIPHER_ID: u8 = 1;
const ARGON_VERSION: u32 = 0x13;
const MEMORY_KIB: u32 = 64 * 1024;
const PASSES: u32 = 3;
const LANES: u32 = 4;
const AUTH_ERROR: &str = "Wrong password or damaged vault.";

pub struct Session {
    pub data: Vault,
    key: Zeroizing<[u8; 32]>,
    salt: [u8; 16],
}

impl Session {
    pub fn create(master: &str) -> Result<Self> {
        ensure!(!master.is_empty(), "Master password must not be empty.");
        let mut salt = [0_u8; 16];
        random_bytes(&mut salt)?;
        let key = derive_key(master, &salt)?;
        Ok(Self {
            data: Vault::default(),
            key,
            salt,
        })
    }

    pub fn unlock(bytes: &[u8], master: &str) -> Result<Self> {
        // Complete structural validation precedes both allocation and Argon2.
        let header = ParsedHeader::parse(bytes)?;
        let key = derive_key(master, &header.salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| anyhow!("Could not initialize encryption."))?;
        let mut plaintext = Zeroizing::new(bytes[HEADER_SIZE..].to_vec());
        cipher
            .decrypt_in_place(
                XNonce::from_slice(&header.nonce),
                &bytes[..HEADER_SIZE],
                &mut *plaintext,
            )
            .map_err(|_| anyhow!(AUTH_ERROR))?;
        // Never propagate serde errors: they can quote decrypted user data.
        let data: Vault = serde_json::from_slice(&plaintext)
            .map_err(|_| anyhow!("Authenticated vault payload is invalid."))?;
        data.validate()
            .map_err(|_| anyhow!("Authenticated vault payload is invalid."))?;
        Ok(Self {
            data,
            key,
            salt: header.salt,
        })
    }

    /// Seal candidate data without changing the last committed in-memory state.
    pub fn seal(&self, data: &Vault) -> Result<Vec<u8>> {
        data.validate()?;
        let mut plaintext = Zeroizing::new(Vec::new());
        serde_json::to_writer(
            BoundedWriter {
                buffer: &mut plaintext,
                limit: MAX_CIPHERTEXT_SIZE - TAG_SIZE,
            },
            data,
        )
        .map_err(|_| anyhow!("Vault cannot be serialized within the size limit."))?;
        self.encrypt_payload(&mut plaintext)
    }

    fn encrypt_payload(&self, plaintext: &mut Zeroizing<Vec<u8>>) -> Result<Vec<u8>> {
        let ciphertext_len = plaintext
            .len()
            .checked_add(TAG_SIZE)
            .ok_or_else(|| anyhow!("Vault is too large."))?;
        ensure!(ciphertext_len <= MAX_CIPHERTEXT_SIZE, "Vault is too large.");
        let mut nonce = [0_u8; 24];
        random_bytes(&mut nonce)?;
        let header = encode_header(&self.salt, &nonce, ciphertext_len);
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| anyhow!("Could not initialize encryption."))?;
        cipher
            .encrypt_in_place(XNonce::from_slice(&nonce), &header, &mut **plaintext)
            .map_err(|_| anyhow!("Could not encrypt vault."))?;
        let mut result = Vec::with_capacity(HEADER_SIZE + plaintext.len());
        result.extend_from_slice(&header);
        result.extend_from_slice(plaintext);
        Ok(result)
    }
}

fn random_bytes(bytes: &mut [u8]) -> Result<()> {
    getrandom::getrandom(bytes).map_err(|_| anyhow!("Operating-system randomness is unavailable."))
}

fn derive_key(master: &str, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(MEMORY_KIB, PASSES, LANES, Some(32))
        .map_err(|_| anyhow!("Could not initialize key derivation."))?;
    // Argon2's convenience allocator does not wipe its large work area. Own
    // that memory explicitly so success, error, and unwind paths all clear it.
    let mut memory = Zeroizing::new(vec![Block::default(); params.block_count()]);
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; 32]);
    argon
        .hash_password_into_with_memory(master.as_bytes(), salt, key.as_mut(), &mut *memory)
        .map_err(|_| anyhow!("Could not derive encryption key."))?;
    Ok(key)
}

fn encode_header(salt: &[u8; 16], nonce: &[u8; 24], ciphertext_len: usize) -> [u8; HEADER_SIZE] {
    let mut header = [0_u8; HEADER_SIZE];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    header[10] = KDF_ID;
    header[11] = CIPHER_ID;
    header[12..16].copy_from_slice(&ARGON_VERSION.to_le_bytes());
    header[16..20].copy_from_slice(&MEMORY_KIB.to_le_bytes());
    header[20..24].copy_from_slice(&PASSES.to_le_bytes());
    header[24..28].copy_from_slice(&LANES.to_le_bytes());
    header[28..44].copy_from_slice(salt);
    header[44..68].copy_from_slice(nonce);
    header[68..76].copy_from_slice(&(ciphertext_len as u64).to_le_bytes());
    header
}

struct ParsedHeader {
    salt: [u8; 16],
    nonce: [u8; 24],
}

impl ParsedHeader {
    fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= HEADER_SIZE + TAG_SIZE,
            "Vault is truncated or invalid."
        );
        ensure!(
            bytes.len() <= MAX_FILE_SIZE,
            "Vault exceeds the file size limit."
        );
        ensure!(&bytes[..8] == MAGIC, "Not a SimpleCrypt vault.");
        ensure!(
            bytes[8..10] == FORMAT_VERSION.to_le_bytes(),
            "Unsupported vault version."
        );
        ensure!(
            bytes[10] == KDF_ID && bytes[11] == CIPHER_ID,
            "Unsupported vault algorithms."
        );
        ensure!(
            bytes[12..16] == ARGON_VERSION.to_le_bytes()
                && bytes[16..20] == MEMORY_KIB.to_le_bytes()
                && bytes[20..24] == PASSES.to_le_bytes()
                && bytes[24..28] == LANES.to_le_bytes(),
            "Unsupported vault key-derivation profile."
        );
        ensure!(bytes[76..80] == [0; 4], "Unsupported vault header flags.");
        let mut length = [0; 8];
        length.copy_from_slice(&bytes[68..76]);
        let length = u64::from_le_bytes(length);
        if !(TAG_SIZE as u64..=MAX_CIPHERTEXT_SIZE as u64).contains(&length) {
            bail!("Invalid vault ciphertext length.");
        }
        let expected = HEADER_SIZE
            .checked_add(length as usize)
            .ok_or_else(|| anyhow!("Invalid vault ciphertext length."))?;
        ensure!(
            bytes.len() == expected,
            "Vault is truncated or contains trailing data."
        );
        let mut salt = [0; 16];
        let mut nonce = [0; 24];
        salt.copy_from_slice(&bytes[28..44]);
        nonce.copy_from_slice(&bytes[44..68]);
        Ok(Self { salt, nonce })
    }
}

/// Bound serialization as it happens, including expansion of JSON escapes.
struct BoundedWriter<'a> {
    buffer: &'a mut Vec<u8>,
    limit: usize,
}

impl Write for BoundedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.buffer.len()) {
            return Err(io::Error::other("Vault payload size limit exceeded."));
        }
        self.buffer.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Field, FieldKind, MAX_FIELD_VALUE_LEN, Record};

    fn fixture() -> Session {
        let mut session = Session::create("synthetic master password").unwrap();
        let mut record = Record::new("sentinel-private-label-秘密").unwrap();
        for kind in FieldKind::ALL {
            let mut field = Field::new(kind.label(), kind);
            field.value = "sentinel-private-value-秘密\n\u{1b}[31m".to_owned();
            record.fields.push(field);
        }
        session.data.records.push(record);
        session
    }

    #[test]
    fn round_trip_all_field_types_and_no_plaintext() {
        let session = fixture();
        let bytes = session.seal(&session.data).unwrap();
        for sentinel in [
            b"sentinel-private-label".as_slice(),
            b"sentinel-private-value".as_slice(),
        ] {
            assert!(!bytes.windows(sentinel.len()).any(|w| w == sentinel));
        }
        let opened = Session::unlock(&bytes, "synthetic master password").unwrap();
        let original = Zeroizing::new(serde_json::to_vec(&session.data).unwrap());
        let restored = Zeroizing::new(serde_json::to_vec(&opened.data).unwrap());
        assert!(original.as_slice() == restored.as_slice());
    }

    #[test]
    fn wrong_password_and_tampering_fail_authentication() {
        let session = fixture();
        let bytes = session.seal(&session.data).unwrap();
        let error = Session::unlock(&bytes, "wrong").err().unwrap();
        assert_eq!(error.to_string(), AUTH_ERROR);
        for offset in [28, 44, HEADER_SIZE, bytes.len() - 1] {
            let mut modified = bytes.clone();
            modified[offset] ^= 1;
            let error = Session::unlock(&modified, "synthetic master password")
                .err()
                .unwrap();
            assert_eq!(error.to_string(), AUTH_ERROR);
        }
    }

    #[test]
    fn repeated_saves_use_fresh_nonces_and_same_profile() {
        let session = fixture();
        let a = session.seal(&session.data).unwrap();
        let b = session.seal(&session.data).unwrap();
        assert_ne!(&a[44..68], &b[44..68]);
        assert_eq!(&a[12..44], &b[12..44]);
        assert_ne!(&a[HEADER_SIZE..], &b[HEADER_SIZE..]);
        assert_eq!(&a[16..20], &65536_u32.to_le_bytes());
        assert_eq!(&a[20..24], &3_u32.to_le_bytes());
        assert_eq!(&a[24..28], &4_u32.to_le_bytes());
    }

    #[test]
    fn bounded_parser_rejects_invalid_headers_without_kdf() {
        let header = encode_header(&[0; 16], &[0; 24], TAG_SIZE);
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(&[0; TAG_SIZE]);
        assert!(ParsedHeader::parse(&bytes).is_ok());
        for offset in [0, 8, 10, 11, 12, 16, 20, 24, 76] {
            let mut changed = bytes.clone();
            changed[offset] ^= 0xff;
            assert!(ParsedHeader::parse(&changed).is_err());
        }
        for length in [0, 15, MAX_CIPHERTEXT_SIZE as u64 + 1, u64::MAX] {
            let mut changed = bytes.clone();
            changed[68..76].copy_from_slice(&length.to_le_bytes());
            assert!(ParsedHeader::parse(&changed).is_err());
        }
        for length in 0..bytes.len() {
            assert!(ParsedHeader::parse(&bytes[..length]).is_err());
        }
        bytes.push(0);
        assert!(ParsedHeader::parse(&bytes).is_err());
        assert!(ParsedHeader::parse(&vec![0; MAX_FILE_SIZE + 1]).is_err());
    }

    #[test]
    fn authenticated_invalid_payloads_are_rejected_without_leaking_data() {
        let session = fixture();
        for payload in [
            br#"{"records":[],"secret-error-sentinel":true}"#.as_slice(),
            br#"{"records":[{"id":"bad","label":"secret-error-sentinel","fields":[]}]}"#.as_slice(),
            b"secret-error-sentinel".as_slice(),
        ] {
            let mut plaintext = Zeroizing::new(payload.to_vec());
            let bytes = session.encrypt_payload(&mut plaintext).unwrap();
            let error = Session::unlock(&bytes, "synthetic master password")
                .err()
                .unwrap();
            assert_eq!(error.to_string(), "Authenticated vault payload is invalid.");
        }
    }

    #[test]
    fn seal_validates_and_bounds_serialization() {
        let mut session = fixture();
        session.data.records[0].fields[0].value = "x".repeat(MAX_FIELD_VALUE_LEN + 1);
        assert!(session.seal(&session.data).is_err());
        let mut buffer = Zeroizing::new(Vec::new());
        let mut writer = BoundedWriter {
            buffer: &mut buffer,
            limit: 3,
        };
        writer.write_all(b"abc").unwrap();
        assert!(writer.write_all(b"d").is_err());
        assert_eq!(buffer.len(), 3);
        assert!(Session::create("").is_err());
    }
}
