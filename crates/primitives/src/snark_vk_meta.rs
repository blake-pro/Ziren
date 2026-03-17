extern crate alloc;

use alloc::{collections::BTreeSet, string::String, vec::Vec};
use core::fmt;

pub const SNARK_VK_META_MAGIC: [u8; 4] = *b"SVM1";
pub const SNARK_VK_META_COMMITMENT_LEN: usize = 32;
const HEADER_LEN: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnarkVkMetaRecord {
    pub version: String,
    pub pc_start: u32,
    pub commitment: [u8; SNARK_VK_META_COMMITMENT_LEN],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnarkVkMetaError {
    Truncated,
    InvalidMagic,
    VersionLenZero,
    InvalidUtf8Version,
    DuplicateVersion,
    EmptyVersion,
    VersionTooLong,
    VersionNotFound,
    TrailingBytes,
    OffsetOverflow,
}

impl fmt::Display for SnarkVkMetaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnarkVkMetaError::Truncated => write!(f, "snark vk meta is truncated"),
            SnarkVkMetaError::InvalidMagic => write!(f, "invalid snark vk meta magic"),
            SnarkVkMetaError::VersionLenZero => write!(f, "version_len must be > 0"),
            SnarkVkMetaError::InvalidUtf8Version => write!(f, "version is not valid utf-8"),
            SnarkVkMetaError::DuplicateVersion => write!(f, "duplicate version found"),
            SnarkVkMetaError::EmptyVersion => write!(f, "version cannot be empty"),
            SnarkVkMetaError::VersionTooLong => write!(f, "version is too long"),
            SnarkVkMetaError::VersionNotFound => write!(f, "version not found"),
            SnarkVkMetaError::TrailingBytes => write!(f, "trailing bytes found"),
            SnarkVkMetaError::OffsetOverflow => write!(f, "offset overflow"),
        }
    }
}

pub fn parse_snark_vk_meta(bytes: &[u8]) -> Result<Vec<SnarkVkMetaRecord>, SnarkVkMetaError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() < HEADER_LEN {
        return Err(SnarkVkMetaError::Truncated);
    }
    if bytes[..4] != SNARK_VK_META_MAGIC {
        return Err(SnarkVkMetaError::InvalidMagic);
    }

    let mut offset = 4usize;
    let count = read_u32_be(bytes, &mut offset)? as usize;
    let mut records = Vec::with_capacity(count);
    let mut seen = BTreeSet::new();

    for _ in 0..count {
        let version_len = read_u16_be(bytes, &mut offset)? as usize;
        if version_len == 0 {
            return Err(SnarkVkMetaError::VersionLenZero);
        }
        let version_bytes = read_bytes(bytes, &mut offset, version_len)?;
        let version = core::str::from_utf8(version_bytes)
            .map_err(|_| SnarkVkMetaError::InvalidUtf8Version)?
            .to_string();
        if !seen.insert(version.clone()) {
            return Err(SnarkVkMetaError::DuplicateVersion);
        }

        let pc_start = read_u32_be(bytes, &mut offset)?;
        let commitment_bytes = read_bytes(bytes, &mut offset, SNARK_VK_META_COMMITMENT_LEN)?;
        let mut commitment = [0u8; SNARK_VK_META_COMMITMENT_LEN];
        commitment.copy_from_slice(commitment_bytes);

        records.push(SnarkVkMetaRecord { version, pc_start, commitment });
    }

    if offset != bytes.len() {
        return Err(SnarkVkMetaError::TrailingBytes);
    }

    Ok(records)
}

pub fn serialize_snark_vk_meta(
    records: &[SnarkVkMetaRecord],
) -> Result<Vec<u8>, SnarkVkMetaError> {
    let mut seen = BTreeSet::new();
    for record in records {
        if record.version.is_empty() {
            return Err(SnarkVkMetaError::EmptyVersion);
        }
        if !seen.insert(record.version.as_str()) {
            return Err(SnarkVkMetaError::DuplicateVersion);
        }
        let _ = u16::try_from(record.version.len()).map_err(|_| SnarkVkMetaError::VersionTooLong)?;
    }

    let mut out = Vec::new();
    out.extend_from_slice(&SNARK_VK_META_MAGIC);
    out.extend_from_slice(&(records.len() as u32).to_be_bytes());
    for record in records {
        let version_bytes = record.version.as_bytes();
        out.extend_from_slice(&(version_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(version_bytes);
        out.extend_from_slice(&record.pc_start.to_be_bytes());
        out.extend_from_slice(&record.commitment);
    }
    Ok(out)
}

pub fn upsert_snark_vk_meta(records: &mut Vec<SnarkVkMetaRecord>, new_record: SnarkVkMetaRecord) {
    if let Some(existing) = records.iter_mut().find(|record| record.version == new_record.version) {
        *existing = new_record;
    } else {
        records.push(new_record);
    }
}

pub fn get_snark_vk_meta_by_version<'a>(
    records: &'a [SnarkVkMetaRecord],
    version: &str,
) -> Result<&'a SnarkVkMetaRecord, SnarkVkMetaError> {
    records
        .iter()
        .find(|record| record.version == version)
        .ok_or(SnarkVkMetaError::VersionNotFound)
}

fn read_bytes<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'a [u8], SnarkVkMetaError> {
    let end = offset.checked_add(len).ok_or(SnarkVkMetaError::OffsetOverflow)?;
    if end > bytes.len() {
        return Err(SnarkVkMetaError::Truncated);
    }
    let out = &bytes[*offset..end];
    *offset = end;
    Ok(out)
}

fn read_u16_be(bytes: &[u8], offset: &mut usize) -> Result<u16, SnarkVkMetaError> {
    let v = read_bytes(bytes, offset, 2)?;
    Ok(u16::from_be_bytes([v[0], v[1]]))
}

fn read_u32_be(bytes: &[u8], offset: &mut usize) -> Result<u32, SnarkVkMetaError> {
    let v = read_bytes(bytes, offset, 4)?;
    Ok(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
}

#[cfg(test)]
mod tests {
    use super::{
        get_snark_vk_meta_by_version, parse_snark_vk_meta, serialize_snark_vk_meta,
        upsert_snark_vk_meta, SnarkVkMetaError, SnarkVkMetaRecord,
    };

    fn sample_record(version: &str, pc_start: u32, value: u8) -> SnarkVkMetaRecord {
        SnarkVkMetaRecord { version: version.to_string(), pc_start, commitment: [value; 32] }
    }

    #[test]
    fn test_parse_serialize_roundtrip() {
        let records = vec![
            sample_record("v1.2.3", 1, 0x11),
            sample_record("v1.2.4", 2, 0x22),
        ];
        let bytes = serialize_snark_vk_meta(&records).expect("serialize");
        let decoded = parse_snark_vk_meta(&bytes).expect("parse");
        assert_eq!(decoded, records);
    }

    #[test]
    fn test_parse_invalid_magic() {
        let mut bytes = serialize_snark_vk_meta(&[sample_record("v1.2.4", 0, 0x11)]).unwrap();
        bytes[0..4].copy_from_slice(b"BAD!");
        assert_eq!(parse_snark_vk_meta(&bytes), Err(SnarkVkMetaError::InvalidMagic));
    }

    #[test]
    fn test_parse_truncated() {
        let mut bytes = serialize_snark_vk_meta(&[sample_record("v1.2.4", 0, 0x11)]).unwrap();
        bytes.pop();
        assert_eq!(parse_snark_vk_meta(&bytes), Err(SnarkVkMetaError::Truncated));
    }

    #[test]
    fn test_parse_duplicate_version_rejected() {
        let records = vec![sample_record("v1.2.4", 0, 0x11), sample_record("v1.2.4", 9, 0x22)];
        assert_eq!(
            serialize_snark_vk_meta(&records),
            Err(SnarkVkMetaError::DuplicateVersion)
        );
    }

    #[test]
    fn test_upsert_append_and_replace() {
        let mut records = vec![sample_record("v1.2.3", 1, 0x11)];
        upsert_snark_vk_meta(&mut records, sample_record("v1.2.4", 2, 0x22));
        assert_eq!(records.len(), 2);
        assert_eq!(
            get_snark_vk_meta_by_version(&records, "v1.2.4")
                .expect("lookup")
                .commitment,
            [0x22; 32]
        );

        upsert_snark_vk_meta(&mut records, sample_record("v1.2.4", 3, 0x33));
        assert_eq!(records.len(), 2);
        let updated = get_snark_vk_meta_by_version(&records, "v1.2.4").expect("lookup");
        assert_eq!(updated.pc_start, 3);
        assert_eq!(updated.commitment, [0x33; 32]);
    }

    #[test]
    fn test_get_missing_version() {
        let records = vec![sample_record("v1.2.4", 0, 0x44)];
        assert_eq!(
            get_snark_vk_meta_by_version(&records, "v-not-exists"),
            Err(SnarkVkMetaError::VersionNotFound)
        );
    }
}
