use alloc::vec::Vec;

use lazy_static::lazy_static;
use zkm_primitives::snark_vk_meta::{
    get_snark_vk_meta_by_version, parse_snark_vk_meta, SnarkVkMetaError, SnarkVkMetaRecord,
};

use crate::error::Error;

const COMMITMENT_LEN: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnarkVkMeta {
    pub pc_start: u32,
    pub commitment: [u8; COMMITMENT_LEN],
}

lazy_static! {
    static ref SNARK_VK_META_RECORDS: Result<Vec<SnarkVkMetaRecord>, Error> =
        parse_snark_vk_meta(*crate::SNARK_VK_META_BYTES).map_err(map_meta_error);
}

pub fn get_snark_vk_meta(version: &str) -> Result<SnarkVkMeta, Error> {
    let records = SNARK_VK_META_RECORDS.as_ref().map_err(|_| Error::InvalidSnarkVkMetaFormat)?;
    let record = get_snark_vk_meta_by_version(records, version).map_err(map_meta_error)?;
    Ok(SnarkVkMeta { pc_start: record.pc_start, commitment: record.commitment })
}

fn map_meta_error(error: SnarkVkMetaError) -> Error {
    match error {
        SnarkVkMetaError::VersionNotFound => Error::VersionNotFound,
        _ => Error::InvalidSnarkVkMetaFormat,
    }
}

#[cfg(test)]
mod tests {
    use super::{get_snark_vk_meta, map_meta_error, SnarkVkMeta};
    use crate::error::Error;
    use zkm_primitives::snark_vk_meta::{
        parse_snark_vk_meta, serialize_snark_vk_meta, SnarkVkMetaError, SnarkVkMetaRecord,
    };

    #[test]
    fn test_parse_invalid_magic_mapped_to_verifier_error() {
        let mut bytes = serialize_snark_vk_meta(&[SnarkVkMetaRecord {
            version: "v0.test".to_string(),
            pc_start: 7,
            commitment: [0x11u8; 32],
        }])
        .expect("serialize");
        bytes[0..4].copy_from_slice(b"BAD!");
        let parse_err = parse_snark_vk_meta(&bytes).expect_err("must fail");
        assert_eq!(map_meta_error(parse_err), Error::InvalidSnarkVkMetaFormat);
    }

    #[test]
    fn test_parse_truncated_mapped_to_verifier_error() {
        let mut bytes = serialize_snark_vk_meta(&[SnarkVkMetaRecord {
            version: "v0.test".to_string(),
            pc_start: 7,
            commitment: [0x11u8; 32],
        }])
        .expect("serialize");
        bytes.pop();
        let parse_err = parse_snark_vk_meta(&bytes).expect_err("must fail");
        assert_eq!(map_meta_error(parse_err), Error::InvalidSnarkVkMetaFormat);
    }

    #[test]
    fn test_parse_duplicate_versions_mapped_to_verifier_error() {
        let bytes = serialize_snark_vk_meta(&[
            SnarkVkMetaRecord {
                version: "v1.2.4".to_string(),
                pc_start: 0,
                commitment: [0x22u8; 32],
            },
            SnarkVkMetaRecord {
                version: "v1.2.4".to_string(),
                pc_start: 1,
                commitment: [0x33u8; 32],
            },
        ]);
        assert_eq!(bytes, Err(SnarkVkMetaError::DuplicateVersion));
    }

    #[test]
    fn test_get_missing_version() {
        assert!(matches!(get_snark_vk_meta("version-not-exists"), Err(Error::VersionNotFound)));
    }

    #[test]
    fn test_get_known_version() {
        let expected = SnarkVkMeta {
            pc_start: 0,
            commitment: [
                0x09, 0xf4, 0x6d, 0x5e, 0x3f, 0x82, 0xee, 0x9c, 0x92, 0xd1, 0xdf, 0x45, 0xd8, 0xfe,
                0x4d, 0xee, 0x29, 0x2c, 0x0c, 0x08, 0x1b, 0x78, 0x61, 0x16, 0x3c, 0x81, 0xc3, 0xea,
                0x23, 0x4e, 0xb8, 0xff,
            ],
        };
        assert_eq!(get_snark_vk_meta("v1.2.4"), Ok(expected));
    }
}
