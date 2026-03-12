#![allow(unused_variables)]
use hashbrown::HashMap;
use zkm_core_executor::{ZKMContext, ZKMReduceProof};
use zkm_core_machine::io::ZKMStdin;
use zkm_stark::{ShardCommitment, ShardOpenedValues, ShardProof, StarkVerifyingKey};

use crate::{
    Prover, ZKMProof, ZKMProofKind, ZKMProofWithPublicValues, ZKMProvingKey, ZKMVerificationError,
    ZKMVerifyingKey,
};
use anyhow::Result;
use num_bigint::BigUint;
use p3_field::FieldAlgebra;
use p3_fri::FriProof;
use p3_koala_bear::KoalaBear;
use zkm_prover::{
    components::DefaultProverComponents, utils::snark_public_input_hash_bytes, DvSnarkBn254Proof,
    Groth16Bn254Proof, HashableKey, PlonkBn254Proof, ZKMProver,
};
use zkm_stark::septic_digest::SepticDigest;

use super::{ProofOpts, ProverType};

/// An implementation of [crate::ProverClient] that can generate mock proofs.
pub struct MockProver {
    pub(crate) prover: ZKMProver,
}

impl MockProver {
    /// Creates a new [MockProver].
    pub fn new() -> Self {
        let prover = ZKMProver::new();
        Self { prover }
    }
}

fn mock_snark_vkey_hash(vkey: &ZKMVerifyingKey) -> String {
    let prehash = [0u8; 32];
    let mut digest = snark_public_input_hash_bytes(&prehash, &vkey.hash_koalabear());
    digest[0] &= 0x1f;
    BigUint::from_bytes_be(&digest).to_string()
}

impl Prover<DefaultProverComponents> for MockProver {
    fn id(&self) -> ProverType {
        ProverType::Mock
    }

    fn setup(&self, elf: &[u8]) -> (ZKMProvingKey, ZKMVerifyingKey) {
        let (pk, _, _, vk) = self.prover.setup(elf);
        (pk, vk)
    }

    fn zkm_prover(&self) -> &ZKMProver {
        &self.prover
    }

    fn prove_impl<'a>(
        &'a self,
        pk: &ZKMProvingKey,
        stdin: ZKMStdin,
        opts: ProofOpts,
        context: ZKMContext<'a>,
        kind: ZKMProofKind,
        _elf_id: Option<String>,
    ) -> Result<(ZKMProofWithPublicValues, u64)> {
        match kind {
            ZKMProofKind::Core => {
                let (public_values, _) = self.prover.execute(&pk.elf, &stdin, context)?;
                Ok((
                    ZKMProofWithPublicValues {
                        proof: ZKMProof::Core(vec![]),
                        public_values,
                        zkm_version: self.version().to_string(),
                    },
                    0,
                ))
            }
            ZKMProofKind::Compressed => {
                let (public_values, _) = self.prover.execute(&pk.elf, &stdin, context)?;

                let shard_proof = ShardProof {
                    commitment: ShardCommitment {
                        main_commit: [KoalaBear::ZERO; 8].into(),
                        permutation_commit: [KoalaBear::ZERO; 8].into(),
                        quotient_commit: [KoalaBear::ZERO; 8].into(),
                    },
                    opened_values: ShardOpenedValues { chips: vec![] },
                    opening_proof: FriProof {
                        commit_phase_commits: vec![],
                        query_proofs: vec![],
                        final_poly: Default::default(),
                        pow_witness: KoalaBear::ZERO,
                    },
                    chip_ordering: HashMap::new(),
                    public_values: vec![],
                };

                let reduce_vk = StarkVerifyingKey {
                    commit: [KoalaBear::ZERO; 8].into(),
                    pc_start: KoalaBear::ZERO,
                    chip_information: vec![],
                    chip_ordering: HashMap::new(),
                    initial_global_cumulative_sum: SepticDigest::zero(),
                };

                let proof = ZKMProof::Compressed(Box::new(ZKMReduceProof {
                    vk: reduce_vk,
                    proof: shard_proof,
                }));

                Ok((
                    ZKMProofWithPublicValues {
                        proof,
                        public_values,
                        zkm_version: self.version().to_string(),
                    },
                    0,
                ))
            }
            ZKMProofKind::Plonk => {
                let (public_values, _) = self.prover.execute(&pk.elf, &stdin, context)?;
                Ok((
                    ZKMProofWithPublicValues {
                        proof: ZKMProof::Plonk(PlonkBn254Proof {
                            public_inputs: [
                                mock_snark_vkey_hash(&pk.vk),
                                public_values.hash_bn254().to_string(),
                            ],
                            encoded_proof: "".to_string(),
                            raw_proof: "".to_string(),
                            plonk_vkey_hash: [0; 32],
                        }),
                        public_values,
                        zkm_version: self.version().to_string(),
                    },
                    0,
                ))
            }
            ZKMProofKind::Groth16 => {
                let (public_values, _) = self.prover.execute(&pk.elf, &stdin, context)?;
                Ok((
                    ZKMProofWithPublicValues {
                        proof: ZKMProof::Groth16(Groth16Bn254Proof {
                            public_inputs: [
                                mock_snark_vkey_hash(&pk.vk),
                                public_values.hash_bn254().to_string(),
                            ],
                            encoded_proof: "".to_string(),
                            raw_proof: "".to_string(),
                            groth16_vkey_hash: [0; 32],
                        }),
                        public_values,
                        zkm_version: self.version().to_string(),
                    },
                    0,
                ))
            }
            ZKMProofKind::DvSnark => {
                let (public_values, _) = self.prover.execute(&pk.elf, &stdin, context)?;
                Ok((
                    ZKMProofWithPublicValues {
                        proof: ZKMProof::DvSnark(DvSnarkBn254Proof {}),
                        public_values,
                        zkm_version: self.version().to_string(),
                    },
                    0,
                ))
            }
            ZKMProofKind::CompressToGroth16 => unreachable!(),
        }
    }

    fn verify(
        &self,
        bundle: &ZKMProofWithPublicValues,
        vkey: &ZKMVerifyingKey,
    ) -> Result<(), ZKMVerificationError> {
        match &bundle.proof {
            ZKMProof::Plonk(PlonkBn254Proof { public_inputs, .. }) => {
                let expected_vk_hash = mock_snark_vkey_hash(vkey);
                if public_inputs[0] != expected_vk_hash
                    || public_inputs[1] != bundle.public_values.hash_bn254().to_string()
                {
                    return Err(ZKMVerificationError::Plonk(anyhow::anyhow!(
                        "mock plonk public inputs mismatch"
                    )));
                }
                Ok(())
            }
            ZKMProof::Groth16(Groth16Bn254Proof { public_inputs, .. }) => {
                let expected_vk_hash = mock_snark_vkey_hash(vkey);
                if public_inputs[0] != expected_vk_hash
                    || public_inputs[1] != bundle.public_values.hash_bn254().to_string()
                {
                    return Err(ZKMVerificationError::Groth16(anyhow::anyhow!(
                        "mock groth16 public inputs mismatch"
                    )));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

impl Default for MockProver {
    fn default() -> Self {
        Self::new()
    }
}
