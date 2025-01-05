# Examples

## Example 1 : `sha2-rust`

This host program sends the private input pri_input = vec![5u8; 1024] and its hash (hash(pri_input)) to the guest program for verification of the hash value.

### Local Proving

Make any edits to [`run-proving.sh`](host-program/run-proving.sh) and run the program:

```sh
cd zkm-project-template/host-program/sha2-rust
./run-proving.sh sha2-rust
```

The result proof and contract file will be in the contracts/verifier and contracts/src respectively.

### Network Proving

> [!NOTE]
> The proving network may sometimes experience high traffic, causing proof tasks to be queued for hours.

> The proving task requires several stages: queuing, splitting, proving, aggregating and finalizing. Each stage involves a varying duration.

Must set the `PRIVATE_KEY` and `ZKM_PROVER=network` in [`run-proving.sh`](host-program/run-proving.sh) and run the program:

```sh
./run-proving.sh sha2-rust
```

The result proof and contract file will be in the contracts/verifier and contracts/src.

### Deploy the Verifier Contract

If your system does not has Foundry, please install it:

```sh
curl -L https://foundry.paradigm.xyz | bash
```
### Verify the snark proof generateing

```
cd  zkm-project-template/contracts
forge test
```

### Deploy the contract generateing

Please edit the following parameters according your aim blockchain.

```
forge script script/verifier.s.sol:VerifierScript --rpc-url https://eth-sepolia.g.alchemy.com/v2/RH793ZL_pQkZb7KttcWcTlOjPrN0BjOW --private-key df4bc5647fdb9600ceb4943d4adff3749956a8512e5707716357b13d5ee687d9
```

For more details, please refer to [this](contracts/README.md) guide.


## Example 2 : `revme`

The revme guest program takes a block data as input and its running is as same as the sha2-rust. Here, the focus is on explaining how to generate block data(the revme's input).

### Generating the public input about a specific block

> [!NOTE]
> The local node connects  ZKM test chain in the following example. You must use the Eth-Compatible local node.

```sh
cd ~
git clone https://github.com/zkMIPS/revme
cd revme
RPC_URL=http://localhost:8545 CHAIN_ID=1337 BLOCK_NO=244 RUST_LOG=debug SUITE_JSON_PATH=./test-vectors/244.json cargo run --example process
```

If successfully, it will generate `244.json` in the path test-vectors

```sh
cp test-vectors/244.json zkm-project-template/host-program/test-vectors/
```

Next, you need to edit the `JSON_PATH` variable in the [`run-proving.sh`](host-program/revme/run-proving.sh) to match the name of the  JSON file mentioned above.

Then, you can execute the run-proving.sh by following the steps outlined in `Example 1: sha2-rust`.