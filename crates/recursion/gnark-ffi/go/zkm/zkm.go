package zkm

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/ProjectZKM/zkm-recursion-gnark/zkm/koalabear"
	"github.com/ProjectZKM/zkm-recursion-gnark/zkm/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

var srsFile string = "srs.bin"
var srsLagrangeFile string = "srs_lagrange.bin"
var constraintsJsonFile string = "constraints.json"
var plonkVerifierContractPath string = "PlonkVerifier.sol"
var groth16VerifierContractPath string = "Groth16Verifier.sol"
var plonkCircuitPath string = "plonk_circuit.bin"
var groth16CircuitPath string = "groth16_circuit.bin"
var plonkVkPath string = "plonk_vk.bin"
var groth16VkPath string = "groth16_vk.bin"
var plonkPkPath string = "plonk_pk.bin"
var groth16PkPath string = "groth16_pk.bin"
var plonkWitnessPath string = "plonk_witness.json"
var groth16WitnessPath string = "groth16_witness.json"
var dvsnarkWitnessPath string = "dvsnark_witness.json"

type Circuit struct {
	VkeyHash              frontend.Variable `gnark:",public"`
	CommittedValuesDigest frontend.Variable `gnark:",public"`
	Vars                  []frontend.Variable
	Felts                 []koalabear.Variable
	Exts                  []koalabear.ExtensionVariable
}

type Constraint struct {
	Opcode string     `json:"opcode"`
	Args   [][]string `json:"args"`
}

type WitnessInput struct {
	Vars                  []string   `json:"vars"`
	Felts                 []string   `json:"felts"`
	Exts                  [][]string `json:"exts"`
	VkeyHash              string     `json:"vkey_hash"`
	CommittedValuesDigest string     `json:"committed_values_digest"`
}

type Proof struct {
	PublicInputs [2]string `json:"public_inputs"`
	EncodedProof string    `json:"encoded_proof"`
	RawProof     string    `json:"raw_proof"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	// Get the file name from an environment variable.
	fileName := os.Getenv("CONSTRAINTS_JSON")
	if fileName == "" {
		fileName = "constraints.json"
	}

	// Read the file.
	data, err := os.ReadFile(fileName)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Deserialize the JSON data into a slice of Instruction structs.
	var constraints []Constraint
	err = json.Unmarshal(data, &constraints)
	if err != nil {
		return fmt.Errorf("error deserializing JSON: %v", err)
	}

	hashAPI := poseidon2.NewChip(api)
	hashKoalaBearAPI := poseidon2.NewKoalaBearChip(api)
	fieldAPI := koalabear.NewChip(api)
	vars := make(map[string]frontend.Variable)
	felts := make(map[string]koalabear.Variable)
	exts := make(map[string]koalabear.ExtensionVariable)

	// Iterate through the witnesses and range check them, if necessary.
	for i := 0; i < len(circuit.Felts); i++ {
		if os.Getenv("GROTH16") != "1" {
			fieldAPI.RangeChecker.Check(circuit.Felts[i].Value, 31)
		} else {
			api.ToBinary(circuit.Felts[i].Value, 31)
		}
	}
	for i := 0; i < len(circuit.Exts); i++ {
		for j := 0; j < 4; j++ {
			if os.Getenv("GROTH16") != "1" {
				fieldAPI.RangeChecker.Check(circuit.Exts[i].Value[j].Value, 31)
			} else {
				api.ToBinary(circuit.Exts[i].Value[j].Value, 31)
			}
		}
	}

	// Iterate through the instructions and handle each opcode.
	for _, cs := range constraints {
		switch cs.Opcode {
		case "ImmV":
			vars[cs.Args[0][0]] = frontend.Variable(cs.Args[1][0])
		case "ImmF":
			felts[cs.Args[0][0]] = koalabear.NewF(cs.Args[1][0])
		case "ImmE":
			exts[cs.Args[0][0]] = koalabear.NewE(cs.Args[1])
		case "AddV":
			vars[cs.Args[0][0]] = api.Add(vars[cs.Args[1][0]], vars[cs.Args[2][0]])
		case "AddF":
			felts[cs.Args[0][0]] = fieldAPI.AddF(felts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "AddE":
			exts[cs.Args[0][0]] = fieldAPI.AddE(exts[cs.Args[1][0]], exts[cs.Args[2][0]])
		case "AddEF":
			exts[cs.Args[0][0]] = fieldAPI.AddEF(exts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "SubV":
			vars[cs.Args[0][0]] = api.Sub(vars[cs.Args[1][0]], vars[cs.Args[2][0]])
		case "SubF":
			felts[cs.Args[0][0]] = fieldAPI.SubF(felts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "DivF":
			felts[cs.Args[0][0]] = fieldAPI.DivF(felts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "SubE":
			exts[cs.Args[0][0]] = fieldAPI.SubE(exts[cs.Args[1][0]], exts[cs.Args[2][0]])
		case "SubEF":
			exts[cs.Args[0][0]] = fieldAPI.SubEF(exts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "MulV":
			vars[cs.Args[0][0]] = api.Mul(vars[cs.Args[1][0]], vars[cs.Args[2][0]])
		case "MulF":
			felts[cs.Args[0][0]] = fieldAPI.MulF(felts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "MulE":
			exts[cs.Args[0][0]] = fieldAPI.MulE(exts[cs.Args[1][0]], exts[cs.Args[2][0]])
		case "MulEF":
			exts[cs.Args[0][0]] = fieldAPI.MulEF(exts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "DivE":
			exts[cs.Args[0][0]] = fieldAPI.DivE(exts[cs.Args[1][0]], exts[cs.Args[2][0]])
		case "DivEF":
			exts[cs.Args[0][0]] = fieldAPI.DivEF(exts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "NegE":
			exts[cs.Args[0][0]] = fieldAPI.NegE(exts[cs.Args[1][0]])
		case "InvE":
			exts[cs.Args[0][0]] = fieldAPI.InvE(exts[cs.Args[1][0]])
		case "Num2BitsV":
			numBits, err := strconv.Atoi(cs.Args[2][0])
			if err != nil {
				return fmt.Errorf("error converting number of bits to int: %v", err)
			}
			bits := api.ToBinary(vars[cs.Args[1][0]], numBits)
			for i := 0; i < len(cs.Args[0]); i++ {
				vars[cs.Args[0][i]] = bits[i]
			}
		case "Num2BitsF":
			bits := fieldAPI.ToBinary(felts[cs.Args[1][0]])
			for i := 0; i < len(cs.Args[0]); i++ {
				vars[cs.Args[0][i]] = bits[i]
			}
		case "Permute":
			state := [3]frontend.Variable{vars[cs.Args[0][0]], vars[cs.Args[1][0]], vars[cs.Args[2][0]]}
			hashAPI.PermuteMut(&state)
			vars[cs.Args[0][0]] = state[0]
			vars[cs.Args[1][0]] = state[1]
			vars[cs.Args[2][0]] = state[2]
		case "PermuteKoalaBear":
			var state [16]koalabear.Variable
			for i := 0; i < 16; i++ {
				state[i] = felts[cs.Args[i][0]]
			}
			hashKoalaBearAPI.PermuteMut(&state)
			for i := 0; i < 16; i++ {
				felts[cs.Args[i][0]] = state[i]
			}
		case "SelectV":
			vars[cs.Args[0][0]] = api.Select(vars[cs.Args[1][0]], vars[cs.Args[2][0]], vars[cs.Args[3][0]])
		case "SelectF":
			felts[cs.Args[0][0]] = fieldAPI.SelectF(vars[cs.Args[1][0]], felts[cs.Args[2][0]], felts[cs.Args[3][0]])
		case "SelectE":
			exts[cs.Args[0][0]] = fieldAPI.SelectE(vars[cs.Args[1][0]], exts[cs.Args[2][0]], exts[cs.Args[3][0]])
		case "Ext2Felt":
			out := fieldAPI.Ext2Felt(exts[cs.Args[4][0]])
			for i := 0; i < 4; i++ {
				felts[cs.Args[i][0]] = out[i]
			}
		case "AssertEqV":
			api.AssertIsEqual(vars[cs.Args[0][0]], vars[cs.Args[1][0]])
		case "AssertEqF":
			fieldAPI.AssertIsEqualF(felts[cs.Args[0][0]], felts[cs.Args[1][0]])
		case "AssertNeF":
			fieldAPI.AssertNotEqualF(felts[cs.Args[0][0]], felts[cs.Args[1][0]])
		case "AssertEqE":
			fieldAPI.AssertIsEqualE(exts[cs.Args[0][0]], exts[cs.Args[1][0]])
		case "PrintV":
			api.Println(vars[cs.Args[0][0]])
		case "PrintF":
			f := fieldAPI.ReduceSlow(felts[cs.Args[0][0]])
			api.Println(f.Value)
		case "PrintE":
			e := fieldAPI.ReduceE(exts[cs.Args[0][0]])
			api.Println(e.Value[0].Value)
			api.Println(e.Value[1].Value)
			api.Println(e.Value[2].Value)
			api.Println(e.Value[3].Value)
		case "WitnessV":
			i, err := strconv.Atoi(cs.Args[1][0])
			if err != nil {
				panic(err)
			}
			vars[cs.Args[0][0]] = circuit.Vars[i]
		case "WitnessF":
			i, err := strconv.Atoi(cs.Args[1][0])
			if err != nil {
				panic(err)
			}
			felts[cs.Args[0][0]] = circuit.Felts[i]
		case "WitnessE":
			i, err := strconv.Atoi(cs.Args[1][0])
			if err != nil {
				panic(err)
			}
			exts[cs.Args[0][0]] = circuit.Exts[i]
		case "CommitVkeyHash":
			if len(cs.Args) != 10 {
				return fmt.Errorf("CommitVkeyHash expects 10 args, got %d", len(cs.Args))
			}

			uapi, err := uints.New[uints.U32](api)
			if err != nil {
				return fmt.Errorf("failed to initialize uint api: %w", err)
			}

			// h1 = sha256(vk_pc_start_be || vk_commitment_be)
			pcStartFelt := felts[cs.Args[0][0]]
			vkCommitment := vars[cs.Args[1][0]]
			pcStartBytes := fixedWidthBEBytesFromVariable(api, uapi, pcStartFelt.Value, 31, 4)
			commitmentBytes := fixedWidthBEBytesFromVariable(api, uapi, vkCommitment, 254, 32)
			h1Input := append(pcStartBytes, commitmentBytes...)
			h1Hasher, err := sha2.New(api)
			if err != nil {
				return fmt.Errorf("failed to create sha2 hasher (h1): %w", err)
			}
			h1Hasher.Write(h1Input)
			h1 := h1Hasher.Sum()

			// h2 = sha256(h1 || zkm_vk_digest_be)
			zkmDigestBytes := make([]uints.U8, 0, 32)
			for i := 2; i < 10; i++ {
				digestWord := felts[cs.Args[i][0]]
				zkmDigestBytes = append(
					zkmDigestBytes,
					fixedWidthBEBytesFromVariable(api, uapi, digestWord.Value, 31, 4)...,
				)
			}
			h2Hasher, err := sha2.New(api)
			if err != nil {
				return fmt.Errorf("failed to create sha2 hasher (h2): %w", err)
			}
			h2Hasher.Write(append(h1, zkmDigestBytes...))
			h2 := h2Hasher.Sum()

			expected := maskedBn254ValueFromSha256Bytes(api, uapi, h2)
			api.AssertIsEqual(circuit.VkeyHash, expected)
		case "CommitCommittedValuesDigest":
			element := vars[cs.Args[0][0]]
			api.AssertIsEqual(circuit.CommittedValuesDigest, element)
		case "CircuitFelts2Ext":
			exts[cs.Args[0][0]] = koalabear.Felts2Ext(felts[cs.Args[1][0]], felts[cs.Args[2][0]], felts[cs.Args[3][0]], felts[cs.Args[4][0]])
		case "CircuitFelt2Var":
			vars[cs.Args[0][0]] = fieldAPI.ReduceSlow(felts[cs.Args[1][0]]).Value
		case "ReduceE":
			exts[cs.Args[0][0]] = fieldAPI.ReduceE(exts[cs.Args[0][0]])
		default:
			return fmt.Errorf("unhandled opcode: %s", cs.Opcode)
		}
	}

	return nil
}

func fixedWidthBEBytesFromVariable(
	api frontend.API,
	uapi *uints.BinaryField[uints.U32],
	value frontend.Variable,
	bitLen int,
	byteLen int,
) []uints.U8 {
	leBits := api.ToBinary(value, bitLen)
	beBytes := make([]uints.U8, byteLen)

	for beIdx := 0; beIdx < byteLen; beIdx++ {
		leByteIdx := byteLen - 1 - beIdx
		byteBits := make([]frontend.Variable, 8)
		for bit := 0; bit < 8; bit++ {
			bitIdx := leByteIdx*8 + bit
			if bitIdx < bitLen {
				byteBits[bit] = leBits[bitIdx]
			} else {
				byteBits[bit] = frontend.Variable(0)
			}
		}
		beBytes[beIdx] = uapi.ByteValueOf(api.FromBinary(byteBits...))
	}

	return beBytes
}

func maskedBn254ValueFromSha256Bytes(
	api frontend.API,
	uapi *uints.BinaryField[uints.U32],
	digest []uints.U8,
) frontend.Variable {
	if len(digest) != 32 {
		panic("sha256 digest must be 32 bytes")
	}

	firstByteBits := api.ToBinary(digest[0].Val, 8)
	firstByteBits[5] = frontend.Variable(0)
	firstByteBits[6] = frontend.Variable(0)
	firstByteBits[7] = frontend.Variable(0)
	maskedFirstByte := uapi.ByteValueOf(api.FromBinary(firstByteBits...))

	acc := frontend.Variable(0)
	for i := 0; i < 32; i++ {
		var current frontend.Variable
		if i == 0 {
			current = maskedFirstByte.Val
		} else {
			current = digest[i].Val
		}
		acc = api.Add(api.Mul(acc, 256), current)
	}
	return acc
}
