use sha2::{Digest, Sha256};
use substrate_bn::Fr;

use crate::error::Error;
use crate::snark_vk_meta::SnarkVkMeta;

/// Hashes the public inputs in the same format as the Plonk and Groth16 verifiers.
pub fn hash_public_inputs(public_inputs: &[u8]) -> [u8; 32] {
    let mut result = Sha256::digest(public_inputs);

    // The Plonk and Groth16 verifiers operate over a 254 bit field, so we need to zero
    // out the first 3 bits. The same logic happens in the Ziren Ethereum verifier contract.
    result[0] &= 0x1F;

    result.into()
}

/// Computes the first SNARK public input from SNARK vk metadata and zkm vk digest bytes.
pub fn snark_public_input_hash_from_meta(
    snark_vk_meta: &SnarkVkMeta,
    zkm_vk_digest: &[u8; 32],
) -> [u8; 32] {
    let mut h1_input = [0u8; 36];
    h1_input[..4].copy_from_slice(&snark_vk_meta.pc_start.to_be_bytes());
    h1_input[4..].copy_from_slice(&snark_vk_meta.commitment);
    let h1: [u8; 32] = Sha256::digest(h1_input).into();

    let mut h2_input = [0u8; 64];
    h2_input[..32].copy_from_slice(&h1);
    h2_input[32..].copy_from_slice(zkm_vk_digest);
    let mut h2: [u8; 32] = Sha256::digest(h2_input).into();

    // The verifier operates over a 254-bit field; zero out the top 3 bits.
    h2[0] &= 0x1F;
    h2
}

/// Formats the Ziren vkey hash and public inputs for use in either the Plonk or Groth16 verifier.
pub fn bn254_public_values(zkm_vkey_hash: &[u8; 32], zkm_public_inputs: &[u8]) -> [Fr; 2] {
    let committed_values_digest = hash_public_inputs(zkm_public_inputs);
    let vkey_hash = Fr::from_slice(&zkm_vkey_hash[1..]).unwrap();
    let committed_values_digest = Fr::from_slice(&committed_values_digest).unwrap();
    [vkey_hash, committed_values_digest]
}

/// Decodes the Ziren verifier input hash from a `0x`-prefixed hex string.
pub fn decode_zkm_vkey_hash(zkm_vkey_hash: &str) -> Result<[u8; 32], Error> {
    let bytes = hex::decode(&zkm_vkey_hash[2..]).map_err(|_| Error::InvalidProgramVkeyHash)?;
    bytes.try_into().map_err(|_| Error::InvalidProgramVkeyHash)
}

#[cfg(test)]
mod tests {
    use super::snark_public_input_hash_from_meta;
    use crate::SnarkVkMeta;

    fn digest_be_from_words(words: [u32; 8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, word) in words.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    }

    #[test]
    fn test_snark_public_input_hash_from_meta_vector() {
        let meta = SnarkVkMeta {
            pc_start: 0x01020304,
            commitment: [
                0x2f, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                0xcc, 0xdd, 0xee, 0xff,
            ],
        };
        let digest_be = digest_be_from_words([
            0x00000000, 0x00000001, 0x7f000000, 0x12345678, 0x0badc0de, 0x0000beef, 0x01020304,
            0x70000000,
        ]);

        let hash = snark_public_input_hash_from_meta(&meta, &digest_be);
        assert_eq!(
            encode_hex(&hash),
            "1c8f70cfe3b73ba3512ef4220e97597881b08a9ff79f0147a2df6d8d0133c4e6"
        );
    }

    #[test]
    fn test_snark_public_input_hash_from_meta_changes_on_any_input_change() {
        let meta = SnarkVkMeta { pc_start: 7, commitment: [0x11; 32] };
        let digest_be = [0x22; 32];
        let base = snark_public_input_hash_from_meta(&meta, &digest_be);

        let changed_pc = SnarkVkMeta { pc_start: 8, commitment: meta.commitment };
        let changed_pc_hash = snark_public_input_hash_from_meta(&changed_pc, &digest_be);
        assert_ne!(base, changed_pc_hash);

        let mut changed_commitment = meta.commitment;
        changed_commitment[0] ^= 0x01;
        let changed_commitment_meta =
            SnarkVkMeta { pc_start: meta.pc_start, commitment: changed_commitment };
        let changed_commitment_hash =
            snark_public_input_hash_from_meta(&changed_commitment_meta, &digest_be);
        assert_ne!(base, changed_commitment_hash);

        let mut changed_digest = digest_be;
        changed_digest[0] ^= 0x01;
        let changed_digest_hash = snark_public_input_hash_from_meta(&meta, &changed_digest);
        assert_ne!(base, changed_digest_hash);
    }
}
