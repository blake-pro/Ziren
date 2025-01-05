# Overview

This is a [template](https://github.com/zkMIPS/zkm-project-template.git) for creating an end-to-end ZKM project which can generate the EVM-Compatible proof and the on chain verification contract.

There are two ways to prove the guest program:

- Use your local machine
- Use ZKM proof network

## Running diagram

![image](./temp-run-diagram.png)

## Getting Started

First to install zkm toolchain run the following command and follow the instructions:
```sh
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/zkMIPS/toolchain/refs/heads/main/setup.sh | sh
source ~/.zkm-toolchain/env
```

## Running the project

### Download the repo

```sh
git clone https://github.com/zkMIPS/zkm-project-template.git
```

### Build

```sh
cd zkm-project-template
sdk/src/local/libsnark/compile.sh  # compile snark library
cargo build --release              # build host and guest programs
```

> [!NOTE]
> You can run the guest program without generating a proof by setting the environmental variable `EXECUTE_ONLY` to "true".https://github.com/zkMIPS/zkm/issues/152

> You can set the `ZKM_SKIP_PROGRAM_BUILD` environment variable to `true` to skip building the guest program when use `zkm_build::build_program`.

> If your program is written in Golang, it needs to be manually compiled into mips.
```sh
GOOS=linux GOARCH=mips GOMIPS=softfloat go build  -o your_guest # replace your_guest to your guest programs
``` 

> The SDK has a libary(libsnark) which supports local proving. If the libsnark is required, please specify the features = ["snark"] in your Cargo.toml. To disable libsnark, set the environment variable NO_USE_SNARK to true when compiling the SDK.


### Generate groth16 proof and verifier contract

> [!NOTE]
> 1. There is a script program available: run_proving.sh. The script facilitate the generation of proofs on the local machine and over the proof network.

> 2. There are four guest programs(sha2-rust, sha2-go, mem-alloc-vec,revme). The following will use sha2-rust and revme as an example to demonstrate local and network proofs.

> 3. If the environmental variable `PROOF_RESULTS_PATH` is not set, the proof results file will be saved in zkm-project-template/contracts/{src, verifier}; if the environmental variable `PROOF_RESULTS_PATH` is set, after the proof is completed, the proof results file needs to be copied from from 'PROOF_RESULTS_PATH'/{src, verifier} to the corresponding zkm-project-template/contracts/{src, verifier}. 

> 4. The environment variable `VERIFYING_KEY_PATH` specifies the location of the verification key (vk). If this variable is not set to zkm-project-template/contracts/src, you should copy the  `VERIFYING_KEY_PATH`/verifier.sol to zkm-project-template/contracts/src/ after executing the host program.

> 5. The environment variable `SETUP_FLAG` is set to "true", it will generate  the proof key (pk), the verification key (vk) and the verifier contract and store them at the path indicated by `VERIFYING_KEY_PATH`.Then, the `SETUP_FLAG` should be set to "false" , next executing the host will generate the snark proof using the same pk and vk.

> [!WARNING]
>  The environmental variable `SEG_SIZE` in the run-xxx_proving.sh affects the final proof generation. 

>  The guest program's ELF with the input is split into segments according the SEG_SIZE, based on the cycle count.

>  When generating proofs on the local machine, if the log shows "[the seg_num is:1 ]", please reduce SEG_SIZE or increase the input. If generating proofs through the proof network, SEG_SIZE must be within the range [65536, 262144]. 

## Local Proving Requirements

- Hardware: X86_64 CPU, 32 cores, 13GB memory (minimum)
- OS: Linux
- Rust: 1.81.0-nightly
- Go : 1.22.1
- Set up a local node for some blockchain(eg, sepolia)

## Network Proving Requirements

- Hardware: X86_64 CPU, 8 cores, 8G memory
- OS: Linux
- Rust: 1.81.0-nightly
- Go : 1.22.1
- CA certificate: ca.pem, ca.key
- [Register](https://www.zkm.io/apply) your address to use
- RPC for a blockchain (eg, sepolia)

> [!NOTE]
> All actions are assumed to be from the base directory `zkm-project-template`