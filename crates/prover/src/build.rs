use p3_koala_bear::KoalaBear;
use p3_field::PrimeField32;
use std::{borrow::Borrow, fs::metadata, path::PathBuf};
use zkm_core_executor::ZKMContext;
use zkm_core_machine::ZKM_CIRCUIT_VERSION;
use zkm_core_machine::io::ZKMStdin;
use zkm_recursion_circuit::machine::{ZKMCompressWitnessValues, ZKMWrapVerifier};
use zkm_recursion_compiler::{
    config::OuterConfig,
    constraints::{Constraint, ConstraintCompiler},
    ir::Builder,
};

use zkm_recursion_core::air::RecursionPublicValues;
pub use zkm_recursion_core::stark::zkm_dev_mode;

pub use zkm_recursion_circuit::witness::{OuterWitness, Witnessable};

use zkm_recursion_gnark_ffi::{DvSnarkBn254Prover, Groth16Bn254Prover, PlonkBn254Prover};
use zkm_stark::{ShardProof, StarkVerifyingKey, ZKMProverOpts};

use crate::{
    snark_vk_meta::{
        read_snark_vk_meta_or_empty, upsert_snark_vk_meta, write_snark_vk_meta, SnarkVkMetaRecord,
    },
    utils::{
        koalabear_bytes_to_bn254, outer_vk_commitment_be_bytes, snark_public_input_from_outer_vk,
        words_to_bytes,
    },
    OuterSC, WrapAir, ZKMProver,
};

fn write_snark_vkey_hash_meta(template_vk: &StarkVerifyingKey<OuterSC>, build_dir: &PathBuf) {
    let baseline_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../verifier/bn254-vk/snark_vk_meta.bin");
    let mut records = read_snark_vk_meta_or_empty(&baseline_path)
        .expect("failed to read baseline snark_vk_meta.bin");

    let commitment_bytes = outer_vk_commitment_be_bytes(template_vk);
    let commitment: [u8; 32] = commitment_bytes
        .as_slice()
        .try_into()
        .expect("outer vk commitment must be exactly 32 bytes");

    upsert_snark_vk_meta(
        &mut records,
        SnarkVkMetaRecord {
            version: ZKM_CIRCUIT_VERSION.to_string(),
            pc_start: template_vk.pc_start.as_canonical_u32(),
            commitment,
        },
    );

    let output_path = build_dir.join("snark_vk_meta.bin");
    write_snark_vk_meta(&output_path, &records).expect("failed to write snark_vk_meta.bin");
}

/// Tries to build the PLONK artifacts inside the development directory.
pub fn try_build_plonk_bn254_artifacts_dev(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
) -> PathBuf {
    let build_dir = plonk_bn254_artifacts_dev_dir();
    println!("[zkm] building plonk bn254 artifacts in development mode");
    build_plonk_bn254_artifacts(template_vk, template_proof, &build_dir);
    build_dir
}

/// Tries to build the groth16 bn254 artifacts in the current environment.
pub fn try_build_groth16_bn254_artifacts_dev(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
) -> PathBuf {
    let build_dir = groth16_bn254_artifacts_dev_dir();
    println!("[zkm] building groth16 bn254 artifacts in development mode");
    build_groth16_bn254_artifacts(template_vk, template_proof, &build_dir);
    build_dir
}

/// Tries to build the dv-snark bn254 artifacts in the current environment.
pub fn try_build_dvsnark_bn254_artifacts_dev(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
    store_dir: &PathBuf,
) -> PathBuf {
    tracing::info!("build dvsnark artifacts dev");
    let build_dir = dvsnark_bn254_artifacts_dev_dir();

    let r1cs_to_dvsnark_path = store_dir.join("r1cs_to_dvsnark");
    let r1cs_cached_path = store_dir.join("r1cs_cached");

    let mut r1cs_to_dvsnark_content_exist = false;
    if let Ok(md) = metadata(&r1cs_to_dvsnark_path) {
        if md.len() > 1024 {
            r1cs_to_dvsnark_content_exist = true;
        }
    }

    let mut r1cs_cached_content_exist = false;
    if let Ok(md) = metadata(&r1cs_cached_path) {
        if md.len() > 1024 {
            r1cs_cached_content_exist = true;
        }
    }

    if r1cs_cached_content_exist && r1cs_to_dvsnark_content_exist {
        println!("[zkm] build dir contains cached r1cs");
        return build_dir; // early return if content already exist
    }

    println!("[zkm] building dv-snark bn254 artifacts in development mode");
    build_dvsnark_bn254_artifacts(template_vk, template_proof, &build_dir, store_dir);
    build_dir
}

/// Gets the directory where the PLONK artifacts are installed in development mode.
pub fn plonk_bn254_artifacts_dev_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".zkm").join("circuits").join("dev")
}

/// Gets the directory where the groth16 artifacts are installed in development mode.
pub fn groth16_bn254_artifacts_dev_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".zkm").join("circuits").join("dev")
}

/// Gets the directory where the dv-snark artifacts are installed in development mode.
pub fn dvsnark_bn254_artifacts_dev_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".zkm").join("circuits").join("dev")
}

/// Build the plonk bn254 artifacts to the given directory for the given verification key and
/// template proof.
pub fn build_plonk_bn254_artifacts(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
    build_dir: impl Into<PathBuf>,
) {
    let build_dir = build_dir.into();
    std::fs::create_dir_all(&build_dir).expect("failed to create build directory");
    write_snark_vkey_hash_meta(template_vk, &build_dir);
    let (constraints, witness) = build_constraints_and_witness(template_vk, template_proof);
    PlonkBn254Prover::build(constraints, witness, build_dir);
}

/// Build the groth16 bn254 artifacts to the given directory for the given verification key and
/// template proof.
pub fn build_groth16_bn254_artifacts(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
    build_dir: impl Into<PathBuf>,
) {
    let build_dir = build_dir.into();
    std::fs::create_dir_all(&build_dir).expect("failed to create build directory");
    write_snark_vkey_hash_meta(template_vk, &build_dir);
    let (constraints, witness) = build_constraints_and_witness(template_vk, template_proof);
    Groth16Bn254Prover::build(constraints, witness, build_dir);
}

/// Build the dv-snark bn254 artifacts to the given directory for the given verification key and
/// template proof.
pub fn build_dvsnark_bn254_artifacts(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
    build_dir: impl Into<PathBuf>,
    store_dir: impl Into<PathBuf>,
) {
    let build_dir = build_dir.into();
    let store_dir = store_dir.into();
    std::fs::create_dir_all(&build_dir).expect("failed to create build directory");
    std::fs::create_dir_all(&store_dir).expect("failed to create store directory");
    write_snark_vkey_hash_meta(template_vk, &build_dir);
    let (constraints, witness) = build_constraints_and_witness(template_vk, template_proof);
    DvSnarkBn254Prover::build(constraints, witness, build_dir, store_dir);
}

/// Builds the plonk bn254 artifacts to the given directory.
///
/// This may take a while as it needs to first generate a dummy proof and then it needs to compile
/// the circuit.
pub fn build_plonk_bn254_artifacts_with_dummy(build_dir: impl Into<PathBuf>) {
    let (wrap_vk, wrapped_proof) = dummy_proof();
    crate::build::build_plonk_bn254_artifacts(&wrap_vk, &wrapped_proof, build_dir.into());
}

/// Builds the groth16 bn254 artifacts to the given directory.
///
/// This may take a while as it needs to first generate a dummy proof and then it needs to compile
/// the circuit.
pub fn build_groth16_bn254_artifacts_with_dummy(build_dir: impl Into<PathBuf>) {
    let (wrap_vk, wrapped_proof) = dummy_proof();
    crate::build::build_groth16_bn254_artifacts(&wrap_vk, &wrapped_proof, build_dir.into());
}

/// Build the verifier constraints and template witness for the circuit.
pub fn build_constraints_and_witness(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
) -> (Vec<Constraint>, OuterWitness<OuterConfig>) {
    tracing::info!("building verifier constraints");
    let template_input = ZKMCompressWitnessValues {
        vks_and_proofs: vec![(template_vk.clone(), template_proof.clone())],
        is_complete: true,
    };
    let constraints =
        tracing::info_span!("wrap circuit").in_scope(|| build_outer_circuit(&template_input));

    let pv: &RecursionPublicValues<KoalaBear> = template_proof.public_values.as_slice().borrow();
    let vkey_hash = snark_public_input_from_outer_vk(template_vk, &pv.zkm_vk_digest);
    let committed_values_digest_bytes: [KoalaBear; 32] =
        words_to_bytes(&pv.committed_value_digest).try_into().unwrap();
    let committed_values_digest = koalabear_bytes_to_bn254(&committed_values_digest_bytes);

    tracing::info!("building template witness");
    let mut witness = OuterWitness::default();
    template_input.write(&mut witness);
    witness.write_committed_values_digest(committed_values_digest);
    witness.write_vkey_hash(vkey_hash);

    (constraints, witness)
}

/// Generate a dummy proof that we can use to build the circuit. We need this to know the shape of
/// the proof.
pub fn dummy_proof() -> (StarkVerifyingKey<OuterSC>, ShardProof<OuterSC>) {
    let elf = include_bytes!("../elf/mipsel-zkm-zkvm-elf");

    tracing::info!("initializing prover");
    let prover: ZKMProver = ZKMProver::new();
    let opts = ZKMProverOpts::default();
    let context = ZKMContext::default();

    tracing::info!("setup elf");
    let (_, pk_d, program, vk) = prover.setup(elf);

    tracing::info!("prove core");
    let mut stdin = ZKMStdin::new();
    stdin.write(&500u32);
    let core_proof = prover.prove_core(&pk_d, program, &stdin, opts, context).unwrap();

    tracing::info!("compress");
    let compressed_proof = prover.compress(&vk, core_proof, vec![], opts).unwrap();

    tracing::info!("shrink");
    let shrink_proof = prover.shrink(compressed_proof, opts).unwrap();

    tracing::info!("wrap");
    let wrapped_proof = prover.wrap_bn254(shrink_proof, opts).unwrap();

    (wrapped_proof.vk, wrapped_proof.proof)
}

fn build_outer_circuit(template_input: &ZKMCompressWitnessValues<OuterSC>) -> Vec<Constraint> {
    let wrap_machine = WrapAir::wrap_machine(OuterSC::default());

    let wrap_span = tracing::debug_span!("build wrap circuit").entered();
    let mut builder = Builder::<OuterConfig>::default();

    // Get an input variable.
    let input = template_input.read(&mut builder);

    // Verify the proof.
    ZKMWrapVerifier::verify(&mut builder, &wrap_machine, input);

    let mut backend = ConstraintCompiler::<OuterConfig>::default();
    let operations = backend.emit(builder.into_operations());
    wrap_span.exit();

    operations
}
