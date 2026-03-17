use std::path::Path;

use anyhow::{Context, Result};
pub use zkm_primitives::snark_vk_meta::{
    get_snark_vk_meta_by_version, parse_snark_vk_meta, serialize_snark_vk_meta,
    upsert_snark_vk_meta, SnarkVkMetaError, SnarkVkMetaRecord,
};

pub fn read_snark_vk_meta_or_empty(path: &Path) -> Result<Vec<SnarkVkMetaRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read snark vk meta from {}", path.display()))?;
    parse_snark_vk_meta(&bytes)
        .map_err(|e| anyhow::anyhow!("failed to parse snark vk meta: {e}"))
        .with_context(|| format!("source: {}", path.display()))
}

pub fn write_snark_vk_meta(path: &Path, records: &[SnarkVkMetaRecord]) -> Result<()> {
    let bytes = serialize_snark_vk_meta(records)
        .map_err(|e| anyhow::anyhow!("failed to serialize snark vk meta: {e}"))?;
    std::fs::write(path, bytes)
        .with_context(|| format!("failed to write snark vk meta to {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::{
        get_snark_vk_meta_by_version, read_snark_vk_meta_or_empty, upsert_snark_vk_meta,
        write_snark_vk_meta, SnarkVkMetaRecord,
    };

    fn sample_record(version: &str, pc_start: u32, value: u8) -> SnarkVkMetaRecord {
        SnarkVkMetaRecord { version: version.to_string(), pc_start, commitment: [value; 32] }
    }

    #[test]
    fn test_read_write_meta_file_and_missing_baseline() {
        let missing = std::env::temp_dir().join(format!(
            "snark-vk-missing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let records = read_snark_vk_meta_or_empty(&missing).expect("read missing");
        assert!(records.is_empty());

        let dir = std::env::temp_dir().join(format!(
            "snark-vk-meta-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("snark_vk_meta.bin");

        let input = vec![sample_record("v1.2.4", 0, 0x44)];
        write_snark_vk_meta(&path, &input).expect("write");
        let output = read_snark_vk_meta_or_empty(&path).expect("read");
        assert_eq!(output, input);
    }

    #[test]
    fn test_upsert_and_lookup() {
        let mut records = vec![sample_record("v1.2.3", 1, 0x11)];
        upsert_snark_vk_meta(&mut records, sample_record("v1.2.4", 2, 0x22));
        assert_eq!(
            get_snark_vk_meta_by_version(&records, "v1.2.4")
                .expect("lookup")
                .commitment,
            [0x22; 32]
        );
    }
}
