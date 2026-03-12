package zkm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/ProjectZKM/zkm-recursion-gnark/zkm/koalabear"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type vkeyHashVector struct {
	pcStart    uint32
	commitment *big.Int
	zkmDigest  [8]uint32
}

func fixedVkeyHashVector() vkeyHashVector {
	commitment, ok := new(big.Int).SetString("2f23456789abcdeffedcba987654321000112233445566778899aabbccddeeff", 16)
	if !ok {
		panic("failed to parse commitment")
	}
	return vkeyHashVector{
		pcStart:    0x01020304,
		commitment: commitment,
		zkmDigest: [8]uint32{
			0x00000000,
			0x00000001,
			0x7f000000,
			0x12345678,
			0x0badc0de,
			0x0000beef,
			0x01020304,
			0x70000000,
		},
	}
}

func commitmentBytes32(commitment *big.Int) [32]byte {
	src := commitment.Bytes()
	if len(src) > 32 {
		src = src[len(src)-32:]
	}
	var out [32]byte
	copy(out[32-len(src):], src)
	return out
}

func digestBytes32(words [8]uint32) [32]byte {
	var out [32]byte
	for i := 0; i < len(words); i++ {
		copy(out[i*4:(i+1)*4], []byte{
			byte(words[i] >> 24),
			byte(words[i] >> 16),
			byte(words[i] >> 8),
			byte(words[i]),
		})
	}
	return out
}

func computeHashes(v vkeyHashVector) ([32]byte, [32]byte, [32]byte, *big.Int) {
	commitment := commitmentBytes32(v.commitment)
	digest := digestBytes32(v.zkmDigest)

	h1Input := make([]byte, 0, 4+32)
	h1Input = append(
		h1Input,
		byte(v.pcStart>>24),
		byte(v.pcStart>>16),
		byte(v.pcStart>>8),
		byte(v.pcStart),
	)
	h1Input = append(h1Input, commitment[:]...)
	h1 := sha256.Sum256(h1Input)

	h2Input := make([]byte, 0, 64)
	h2Input = append(h2Input, h1[:]...)
	h2Input = append(h2Input, digest[:]...)
	h2 := sha256.Sum256(h2Input)

	h2Masked := h2
	h2Masked[0] &= 0x1f

	return h1, h2, h2Masked, new(big.Int).SetBytes(h2Masked[:])
}

func commitVkeyHashConstraints() []Constraint {
	return []Constraint{
		{Opcode: "WitnessF", Args: [][]string{{"f_pc_start"}, {"0"}}},
		{Opcode: "WitnessV", Args: [][]string{{"v_commitment"}, {"0"}}},
		{Opcode: "WitnessV", Args: [][]string{{"v_committed_digest"}, {"1"}}},
		{Opcode: "WitnessF", Args: [][]string{{"f_d0"}, {"1"}}},
		{Opcode: "WitnessF", Args: [][]string{{"f_d1"}, {"2"}}},
		{Opcode: "WitnessF", Args: [][]string{{"f_d2"}, {"3"}}},
		{Opcode: "WitnessF", Args: [][]string{{"f_d3"}, {"4"}}},
		{Opcode: "WitnessF", Args: [][]string{{"f_d4"}, {"5"}}},
		{Opcode: "WitnessF", Args: [][]string{{"f_d5"}, {"6"}}},
		{Opcode: "WitnessF", Args: [][]string{{"f_d6"}, {"7"}}},
		{Opcode: "WitnessF", Args: [][]string{{"f_d7"}, {"8"}}},
		{
			Opcode: "CommitVkeyHash",
			Args: [][]string{
				{"f_pc_start"},
				{"v_commitment"},
				{"f_d0"},
				{"f_d1"},
				{"f_d2"},
				{"f_d3"},
				{"f_d4"},
				{"f_d5"},
				{"f_d6"},
				{"f_d7"},
			},
		},
		{Opcode: "CommitCommittedValuesDigest", Args: [][]string{{"v_committed_digest"}}},
	}
}

func writeConstraintsFile(t *testing.T, constraints []Constraint) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "constraints.json")

	data, err := json.Marshal(constraints)
	if err != nil {
		t.Fatalf("failed to marshal constraints: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("failed to write constraints: %v", err)
	}
	return path
}

func makeTemplateCircuit() Circuit {
	felts := make([]koalabear.Variable, 9)
	for i := 0; i < len(felts); i++ {
		felts[i] = koalabear.NewF("0")
	}
	vars := make([]frontend.Variable, 2)
	vars[0] = frontend.Variable("0")
	vars[1] = frontend.Variable("0")

	return Circuit{
		VkeyHash:              frontend.Variable("0"),
		CommittedValuesDigest: frontend.Variable("0"),
		Vars:                  vars,
		Felts:                 felts,
	}
}

func makeWitness(v vkeyHashVector, expectedVkeyHash string) Circuit {
	felts := make([]koalabear.Variable, 9)
	felts[0] = koalabear.NewF(strconv.FormatUint(uint64(v.pcStart), 10))
	for i := 0; i < 8; i++ {
		felts[i+1] = koalabear.NewF(strconv.FormatUint(uint64(v.zkmDigest[i]), 10))
	}

	return Circuit{
		VkeyHash:              frontend.Variable(expectedVkeyHash),
		CommittedValuesDigest: frontend.Variable("42"),
		Vars: []frontend.Variable{
			frontend.Variable(v.commitment.String()),
			frontend.Variable("42"),
		},
		Felts: felts,
	}
}

func TestSnarkVkeyHashFixedVector(t *testing.T) {
	vector := fixedVkeyHashVector()
	h1, h2, h2Masked, maskedBigInt := computeHashes(vector)

	if got := hex.EncodeToString(h1[:]); got != "1eda9bedfb468334f32f07075629cfc25f4f4c44d3f8b879517fe730f822193a" {
		t.Fatalf("unexpected h1: %s", got)
	}
	if got := hex.EncodeToString(h2[:]); got != "5c8f70cfe3b73ba3512ef4220e97597881b08a9ff79f0147a2df6d8d0133c4e6" {
		t.Fatalf("unexpected h2: %s", got)
	}
	if got := hex.EncodeToString(h2Masked[:]); got != "1c8f70cfe3b73ba3512ef4220e97597881b08a9ff79f0147a2df6d8d0133c4e6" {
		t.Fatalf("unexpected masked h2: %s", got)
	}
	if got := maskedBigInt.String(); got != "12918197490875836353672850408626191289408280561329280668107775525892102800614" {
		t.Fatalf("unexpected masked decimal: %s", got)
	}
}

func TestCommitVkeyHashConstraint(t *testing.T) {
	assert := test.NewAssert(t)

	vector := fixedVkeyHashVector()
	_, _, _, expected := computeHashes(vector)

	constraintsPath := writeConstraintsFile(t, commitVkeyHashConstraints())
	t.Setenv("CONSTRAINTS_JSON", constraintsPath)

	circuit := makeTemplateCircuit()
	validWitness := makeWitness(vector, expected.String())
	assert.ProverSucceeded(
		&circuit,
		&validWitness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.PLONK),
	)

	badPcStart := vector
	badPcStart.pcStart++
	badPcWitness := makeWitness(badPcStart, expected.String())
	assert.ProverFailed(
		&circuit,
		&badPcWitness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.PLONK),
	)

	badCommitment := vector
	badCommitment.commitment = new(big.Int).Add(vector.commitment, big.NewInt(1))
	badCommitmentWitness := makeWitness(badCommitment, expected.String())
	assert.ProverFailed(
		&circuit,
		&badCommitmentWitness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.PLONK),
	)

	badDigest := vector
	badDigest.zkmDigest[3]++
	badDigestWitness := makeWitness(badDigest, expected.String())
	assert.ProverFailed(
		&circuit,
		&badDigestWitness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.PLONK),
	)
}
