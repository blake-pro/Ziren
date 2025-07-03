//! A simple example showing how to aggregate proofs of multiple programs with ZKM.

use zkm_prover::{components::DefaultProverComponents, InnerSC};
use zkm_recursion_core::Runtime as RecursionRuntime;
use zkm_recursion_circuit::{
    machine::ZKMCompressWitnessValues,
    witness::Witnessable,
};
use zkm_recursion_compiler::{
    config::InnerConfig,
};
use zkm_sdk::{
    include_elf, ProverClient, ZKMProof, ZKMStdin, ZKMProver, install::try_install_circuit_artifacts, provers::ProofOpts,
};
use zkm_stark::{Challenge, MachineProver, StarkGenericConfig, Val, ZKMProverOpts};

/// A program that just runs a simple computation.
const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci");

fn main() {
    // Setup the logger.
    zkm_sdk::utils::setup_logger();

    // Initialize the proving client.
    let client = ProverClient::new();

    // Setup the proving and verifying keys.
    let (fibonacci_pk, _fibonacci_vk) = client.setup(FIBONACCI_ELF);

    // Generate the fibonacci proofs.
    let proof_1 = tracing::info_span!("generate fibonacci proof n=10").in_scope(|| {
        let mut stdin = ZKMStdin::new();
        stdin.write(&10);
        client.prove(&fibonacci_pk, stdin).compressed().run().expect("proving failed")
    });

    let proof_2 = tracing::info_span!("generate fibonacci proof n=20").in_scope(|| {
        let mut stdin = ZKMStdin::new();
        stdin.write(&20);
        client.prove(&fibonacci_pk, stdin).compressed().run().expect("proving failed")
    });
    println!("proof1 public values: {:?}", proof_1.public_values);
    println!("proof2 public values: {:?}", proof_2.public_values);

    println!("generate compressed proofs done");
    // // write the proofs to a file
    // let proofs = vec![proof_1.proof, proof_2.proof];
    // let proofs_json = serde_json::to_string(&proofs).expect("failed to serialize proofs");
    // std::fs::write("proofs.json", proofs_json).expect("failed to write proofs to file");
    //
    // // read the proofs from the file
    // let proofs_json = std::fs::read_to_string("proofs.json").expect("failed to read proofs from file");
    // let proofs: Vec<ZKMProof> = serde_json::from_str(&proofs_json).expect("failed to deserialize proofs");


    //---------------------------------------------------

    let opts = ZKMProverOpts::default();

    let prover: ZKMProver<DefaultProverComponents> = ZKMProver::new();

    let ZKMProof::Compressed(proof1) = proof_1.proof.clone() else { panic!() };
    let ZKMProof::Compressed(proof2) = proof_2.proof.clone() else { panic!() };

    println!("start compressing proofs");
    let proof = prover.compress2(
        vec![*proof1, *proof2],
        opts,
    ).unwrap();
    println!("compress done");
    //---------------------------------------------------

    // let opts = ProofOpts::default();

    // Generate the shrink proof.
    let compress_proof = prover.shrink(proof, opts).unwrap();
    println!("shrink done");
    // Genenerate the wrap proof.
    let outer_proof = prover.wrap_bn254(compress_proof, opts).unwrap();
    println!("wrap_bn254 done");

    let groth16_bn254_artifacts = if zkm_prover::build::zkm_dev_mode() {
        zkm_prover::build::try_build_groth16_bn254_artifacts_dev(
            &outer_proof.vk,
            &outer_proof.proof,
        )
    } else {
        try_install_circuit_artifacts("groth16")
    };

    let groth16_proof = prover.wrap_groth16_bn254(outer_proof, &groth16_bn254_artifacts);
    println!("wrap_groth16_bn254 done");
    prover.verify_groth16_bn254().unwrap();
}
