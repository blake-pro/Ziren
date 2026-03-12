use std::{
    borrow::Borrow,
    fs::{self, File},
    io::Read,
    iter::{Skip, Take},
};

use itertools::Itertools;
use p3_bn254_fr::Bn254Fr;
use p3_field::{FieldAlgebra, PrimeField, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_symmetric::CryptographicHasher;
use sha2::{Digest, Sha256};
use zkm_core_executor::{Executor, Program};
use zkm_core_machine::{io::ZKMStdin, reduce::ZKMReduceProof};
use zkm_recursion_circuit::machine::RootPublicValues;
use zkm_recursion_core::{
    air::{RecursionPublicValues, NUM_PV_ELMS_TO_HASH},
    stark::{KoalaBearPoseidon2Outer, DIGEST_SIZE as OUTER_COMMITMENT_DIGEST_SIZE},
};
use zkm_stark::{koala_bear_poseidon2::MyHash as InnerHash, Word, ZKMCoreOpts, DIGEST_SIZE};

use crate::{InnerSC, OuterSC, ZKMCoreProofData};
use zkm_stark::StarkVerifyingKey;

/// Get the Ziren vkey KoalaBear Poseidon2 digest this reduce proof is representing.
pub fn zkm_vkey_digest_koalabear(
    proof: &ZKMReduceProof<KoalaBearPoseidon2Outer>,
) -> [KoalaBear; 8] {
    let proof = &proof.proof;
    let pv: &RecursionPublicValues<KoalaBear> = proof.public_values.as_slice().borrow();
    pv.zkm_vk_digest
}

/// Get the Ziren vkey Bn Poseidon2 digest this reduce proof is representing.
pub fn zkm_vkey_digest_bn254(proof: &ZKMReduceProof<KoalaBearPoseidon2Outer>) -> Bn254Fr {
    koalabears_to_bn254(&zkm_vkey_digest_koalabear(proof))
}

/// Compute the digest of the public values.
pub fn recursion_public_values_digest(
    config: &InnerSC,
    public_values: &RecursionPublicValues<KoalaBear>,
) -> [KoalaBear; 8] {
    let hash = InnerHash::new(config.perm.clone());
    let pv_array = public_values.as_array();
    hash.hash_slice(&pv_array[0..NUM_PV_ELMS_TO_HASH])
}

pub fn root_public_values_digest(
    config: &InnerSC,
    public_values: &RootPublicValues<KoalaBear>,
) -> [KoalaBear; 8] {
    let hash = InnerHash::new(config.perm.clone());
    let input = (*public_values.zkm_vk_digest())
        .into_iter()
        .chain(
            (*public_values.committed_value_digest())
                .into_iter()
                .flat_map(|word| word.0.into_iter()),
        )
        .collect::<Vec<_>>();
    hash.hash_slice(&input)
}

pub fn is_root_public_values_valid(
    config: &InnerSC,
    public_values: &RootPublicValues<KoalaBear>,
) -> bool {
    let expected_digest = root_public_values_digest(config, public_values);
    for (value, expected) in public_values.digest().iter().copied().zip_eq(expected_digest) {
        if value != expected {
            return false;
        }
    }
    true
}

/// Check if the digest of the public values is correct.
pub fn is_recursion_public_values_valid(
    config: &InnerSC,
    public_values: &RecursionPublicValues<KoalaBear>,
) -> bool {
    let expected_digest = recursion_public_values_digest(config, public_values);
    for (value, expected) in public_values.digest.iter().copied().zip_eq(expected_digest) {
        if value != expected {
            return false;
        }
    }
    true
}

/// Get the committed values Bn Poseidon2 digest this reduce proof is representing.
pub fn zkm_committed_values_digest_bn254(
    proof: &ZKMReduceProof<KoalaBearPoseidon2Outer>,
) -> Bn254Fr {
    let proof = &proof.proof;
    let pv: &RecursionPublicValues<KoalaBear> = proof.public_values.as_slice().borrow();
    let committed_values_digest_bytes: [KoalaBear; 32] =
        words_to_bytes(&pv.committed_value_digest).try_into().unwrap();
    koalabear_bytes_to_bn254(&committed_values_digest_bytes)
}

impl ZKMCoreProofData {
    pub fn save(&self, path: &str) -> Result<(), std::io::Error> {
        let data = serde_json::to_string(self).unwrap();
        fs::write(path, data).unwrap();
        Ok(())
    }
}

/// Get the number of cycles for a given program.
pub fn get_cycles(elf: &[u8], stdin: &ZKMStdin) -> u64 {
    let program = Program::from(elf).unwrap();
    let mut runtime = Executor::new(program, ZKMCoreOpts::default());
    runtime.write_vecs(&stdin.buffer);
    runtime.run_fast().unwrap();
    runtime.state.global_clk
}

/// Load an ELF file from a given path.
pub fn load_elf(path: &str) -> Result<Vec<u8>, std::io::Error> {
    let mut elf_code = Vec::new();
    File::open(path)?.read_to_end(&mut elf_code)?;
    Ok(elf_code)
}

pub fn words_to_bytes<T: Copy>(words: &[Word<T>]) -> Vec<T> {
    words.iter().flat_map(|word| word.0).collect()
}

/// Convert 8 KoalaBear words into a Bn254Fr field element by shifting by 31 bits each time. The last
/// word becomes the least significant bits.
pub fn koalabears_to_bn254(digest: &[KoalaBear; 8]) -> Bn254Fr {
    let mut result = Bn254Fr::ZERO;
    for word in digest.iter() {
        // Since KoalaBear prime is less than 2^31, we can shift by 31 bits each time and still be
        // within the Bn254Fr field, so we don't have to truncate the top 3 bits.
        result *= Bn254Fr::from_canonical_u64(1 << 31);
        result += Bn254Fr::from_canonical_u32(word.as_canonical_u32());
    }
    result
}

/// Convert 32 KoalaBear bytes into a Bn254Fr field element. The first byte's most significant 3 bits
/// (which would become the 3 most significant bits) are truncated.
pub fn koalabear_bytes_to_bn254(bytes: &[KoalaBear; 32]) -> Bn254Fr {
    let mut result = Bn254Fr::ZERO;
    for (i, byte) in bytes.iter().enumerate() {
        debug_assert!(byte < &KoalaBear::from_canonical_u32(256));
        if i == 0 {
            // 32 bytes is more than Bn254 prime, so we need to truncate the top 3 bits.
            result = Bn254Fr::from_canonical_u32(byte.as_canonical_u32() & 0x1f);
        } else {
            result *= Bn254Fr::from_canonical_u32(256);
            result += Bn254Fr::from_canonical_u32(byte.as_canonical_u32());
        }
    }
    result
}

/// Utility method for converting u32 words to bytes in big endian.
pub fn words_to_bytes_be(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        let word_bytes = words[i].to_be_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word_bytes);
    }
    bytes
}

fn pad_to_32_bytes_be(mut value: Vec<u8>) -> [u8; 32] {
    if value.len() > 32 {
        value = value[value.len() - 32..].to_vec();
    }
    let mut out = [0u8; 32];
    out[32 - value.len()..].copy_from_slice(&value);
    out
}

/// Encode a KoalaBear felt into a fixed-width big-endian u32 representation.
pub fn koalabear_u32_be_bytes(value: KoalaBear) -> [u8; 4] {
    value.as_canonical_u32().to_be_bytes()
}

/// Encode an array of KoalaBear digest words as 32-byte big-endian bytes.
pub fn zkm_vk_digest_be_bytes(digest: &[KoalaBear; DIGEST_SIZE]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, word) in digest.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&koalabear_u32_be_bytes(*word));
    }
    out
}

/// Encode an outer vk commitment as fixed-width big-endian bytes.
pub fn outer_vk_commitment_be_bytes(vk: &StarkVerifyingKey<OuterSC>) -> Vec<u8> {
    let commitment: [_; OUTER_COMMITMENT_DIGEST_SIZE] = vk.commit.into();
    commitment
        .iter()
        .flat_map(|value| pad_to_32_bytes_be(value.as_canonical_biguint().to_bytes_be()))
        .collect()
}

/// Computes h1 = sha256(pc_start_be || commitment_be).
pub fn outer_vk_pc_commitment_hash(vk: &StarkVerifyingKey<OuterSC>) -> [u8; 32] {
    let mut input = Vec::with_capacity(4 + 32 * OUTER_COMMITMENT_DIGEST_SIZE);
    input.extend_from_slice(&koalabear_u32_be_bytes(vk.pc_start));
    input.extend_from_slice(&outer_vk_commitment_be_bytes(vk));
    Sha256::digest(input).into()
}

/// Computes h2 = sha256(h1 || zkm_vk_digest_be).
pub fn snark_public_input_hash_bytes(
    vk_pc_commitment_hash: &[u8; 32],
    zkm_vk_digest: &[KoalaBear; DIGEST_SIZE],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(vk_pc_commitment_hash);
    input.extend_from_slice(&zkm_vk_digest_be_bytes(zkm_vk_digest));
    Sha256::digest(input).into()
}

/// Computes the first SNARK public input from outer vk + zkm vk digest.
pub fn snark_public_input_from_outer_vk(
    outer_vk: &StarkVerifyingKey<OuterSC>,
    zkm_vk_digest: &[KoalaBear; DIGEST_SIZE],
) -> p3_bn254_fr::Bn254Fr {
    let h1 = outer_vk_pc_commitment_hash(outer_vk);
    let h2 = snark_public_input_hash_bytes(&h1, zkm_vk_digest);
    let h2_as_koalabear: [KoalaBear; 32] =
        h2.map(|byte| KoalaBear::from_canonical_u32(byte as u32));
    koalabear_bytes_to_bn254(&h2_as_koalabear)
}

pub trait MaybeTakeIterator<I: Iterator>: Iterator<Item = I::Item> {
    fn maybe_skip(self, bound: Option<usize>) -> RangedIterator<Self>
    where
        Self: Sized,
    {
        match bound {
            Some(bound) => RangedIterator::Skip(self.skip(bound)),
            None => RangedIterator::Unbounded(self),
        }
    }

    fn maybe_take(self, bound: Option<usize>) -> RangedIterator<Self>
    where
        Self: Sized,
    {
        match bound {
            Some(bound) => RangedIterator::Take(self.take(bound)),
            None => RangedIterator::Unbounded(self),
        }
    }
}

impl<I: Iterator> MaybeTakeIterator<I> for I {}

pub enum RangedIterator<I> {
    Unbounded(I),
    Skip(Skip<I>),
    Take(Take<I>),
    Range(Take<Skip<I>>),
}

impl<I: Iterator> Iterator for RangedIterator<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            RangedIterator::Unbounded(unbounded) => unbounded.next(),
            RangedIterator::Skip(skip) => skip.next(),
            RangedIterator::Take(take) => take.next(),
            RangedIterator::Range(range) => range.next(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use num_bigint::BigUint;

    use super::*;

    fn encode_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    }

    #[test]
    fn test_zkm_vk_digest_be_bytes_endianness() {
        let words = [
            0x00000000u32,
            0x00000001,
            0x7f000000,
            0x12345678,
            0x0badc0de,
            0x0000beef,
            0x01020304,
            0x70000000,
        ];
        let digest = words.map(KoalaBear::from_canonical_u32);

        let bytes = zkm_vk_digest_be_bytes(&digest);
        assert_eq!(
            encode_hex(&bytes),
            "00000000000000017f000000123456780badc0de0000beef0102030470000000"
        );
    }

    #[test]
    fn test_snark_vkey_hash_fixed_vector() {
        let pc_start = 0x01020304u32;
        let commitment = [
            0x2f, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff,
        ];

        let mut h1_input = Vec::with_capacity(4 + 32);
        h1_input.extend_from_slice(&pc_start.to_be_bytes());
        h1_input.extend_from_slice(&commitment);
        let h1: [u8; 32] = Sha256::digest(h1_input).into();
        assert_eq!(
            encode_hex(&h1),
            "1eda9bedfb468334f32f07075629cfc25f4f4c44d3f8b879517fe730f822193a"
        );

        let words = [
            0x00000000u32,
            0x00000001,
            0x7f000000,
            0x12345678,
            0x0badc0de,
            0x0000beef,
            0x01020304,
            0x70000000,
        ];
        let digest = words.map(KoalaBear::from_canonical_u32);
        let h2 = snark_public_input_hash_bytes(&h1, &digest);
        assert_eq!(
            encode_hex(&h2),
            "5c8f70cfe3b73ba3512ef4220e97597881b08a9ff79f0147a2df6d8d0133c4e6"
        );

        let h2_as_koalabear = h2.map(|b| KoalaBear::from_canonical_u32(b as u32));
        let pi0 = koalabear_bytes_to_bn254(&h2_as_koalabear).as_canonical_biguint();
        assert_eq!(
            pi0,
            BigUint::from_str(
                "12918197490875836353672850408626191289408280561329280668107775525892102800614"
            )
            .unwrap()
        );
    }
}
