use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    str::FromStr,
};

use enum_map::Enum;
use serde::{Deserialize, Serialize};
use strum::{EnumIter, IntoEnumIterator};

/// MIPS AIR Identifiers.
///
/// These identifiers are for the various chips in the mips prover. We need them in the
/// executor to compute the memory cost of the current shard of execution.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, EnumIter, PartialOrd, Ord, Enum,
)]
pub enum MipsAirId {
    /// The CPU chip.
    Cpu = 0,
    /// The program chip.
    Program = 1,
    /// The SHA-256 extend chip.
    ShaExtend = 2,
    /// The SHA-256 compress chip.
    ShaCompress = 3,
    /// The Edwards add assign chip.
    EdAddAssign = 4,
    /// The Edwards decompress chip.
    EdDecompress = 5,
    /// The secp256k1 decompress chip.
    Secp256k1Decompress = 6,
    /// The secp256k1 add assign chip.
    Secp256k1AddAssign = 7,
    /// The secp256k1 double assign chip.
    Secp256k1DoubleAssign = 8,
    /// The secp256r1 decompress chip.
    Secp256r1Decompress = 9,
    /// The secp256r1 add assign chip.
    Secp256r1AddAssign = 10,
    /// The secp256r1 double assign chip.
    Secp256r1DoubleAssign = 11,
    /// The Keccak permute chip.
    KeccakSponge = 48,
    /// The bn254 add assign chip.
    Bn254AddAssign = 13,
    /// The bn254 double assign chip.
    Bn254DoubleAssign = 14,
    /// The bls12-381 add assign chip.
    Bls12381AddAssign = 15,
    /// The bls12-381 double assign chip.
    Bls12381DoubleAssign = 16,
    /// The uint256 mul mod chip.
    Uint256MulMod = 17,
    /// The u256 xu2048 mul chip.
    U256XU2048Mul = 18,
    /// The bls12-381 fp op assign chip.
    Bls12381FpOpAssign = 19,
    /// The bls12-831 fp2 add sub assign chip.
    Bls12831Fp2AddSubAssign = 20,
    /// The bls12-831 fp2 mul assign chip.
    Bls12831Fp2MulAssign = 21,
    /// The bn254 fp2 add sub assign chip.
    Bn254FpOpAssign = 22,
    /// The bn254 fp op assign chip.
    Bn254Fp2AddSubAssign = 23,
    /// The bn254 fp2 mul assign chip.
    Bn254Fp2MulAssign = 24,
    /// The bls12-381 decompress chip.
    Bls12381Decompress = 25,
    /// The syscall core chip.
    SyscallCore = 26,
    /// The syscall precompile chip.
    SyscallPrecompile = 27,
    /// The div rem chip.
    DivRem = 28,
    /// The add sub chip.
    AddSub = 29,
    /// The bitwise chip.
    Bitwise = 30,
    /// The mul chip.
    Mul = 31,
    /// The shift right chip.
    ShiftRight = 32,
    /// The shift left chip.
    ShiftLeft = 33,
    /// The lt chip.
    Lt = 34,
    /// The CloClz chip.
    CloClz = 35,
    /// The branch chip.
    Branch = 36,
    /// The jump chip.
    Jump = 37,
    /// The SyscallInstructionChip.
    SyscallInstrs = 38,
    /// The MemoryInstructionChip.
    MemoryInstrs = 39,
    /// The MiscInstructionChip.
    MiscInstrs = 40,
    /// The memory global init chip.
    MemoryGlobalInit = 41,
    /// The memory global finalize chip.
    MemoryGlobalFinalize = 42,
    /// The memory local chip.
    MemoryLocal = 43,
    /// The global chip.
    Global = 44,
    /// The byte chip.
    Byte = 45,
}

impl MipsAirId {
    /// Returns the AIRs that are not part of precompile shards and not the program or byte AIR.
    #[must_use]
    pub fn core() -> Vec<MipsAirId> {
        vec![
            MipsAirId::Cpu,
            MipsAirId::AddSub,
            MipsAirId::Mul,
            MipsAirId::Bitwise,
            MipsAirId::ShiftLeft,
            MipsAirId::ShiftRight,
            MipsAirId::DivRem,
            MipsAirId::MemoryLocal,
            MipsAirId::Branch,
            MipsAirId::Jump,
            MipsAirId::MemoryInstrs,
            MipsAirId::SyscallInstrs,
            MipsAirId::MiscInstrs,
            MipsAirId::SyscallCore,
            MipsAirId::Global,
        ]
    }

    /// Returns the string representation of the AIR.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Cpu => "Cpu",
            Self::Program => "Program",
            Self::ShaExtend => "ShaExtend",
            Self::ShaCompress => "ShaCompress",
            Self::EdAddAssign => "EdAddAssign",
            Self::EdDecompress => "EdDecompress",
            Self::Secp256k1Decompress => "Secp256k1Decompress",
            Self::Secp256k1AddAssign => "Secp256k1AddAssign",
            Self::Secp256k1DoubleAssign => "Secp256k1DoubleAssign",
            Self::Secp256r1Decompress => "Secp256r1Decompress",
            Self::Secp256r1AddAssign => "Secp256r1AddAssign",
            Self::Secp256r1DoubleAssign => "Secp256r1DoubleAssign",
            Self::KeccakSponge => "KeccakSponge",
            Self::Bn254AddAssign => "Bn254AddAssign",
            Self::Bn254DoubleAssign => "Bn254DoubleAssign",
            Self::Bls12381AddAssign => "Bls12381AddAssign",
            Self::Bls12381DoubleAssign => "Bls12381DoubleAssign",
            Self::Uint256MulMod => "Uint256MulMod",
            Self::U256XU2048Mul => "U256XU2048Mul",
            Self::Bls12381FpOpAssign => "Bls12381FpOpAssign",
            Self::Bls12831Fp2AddSubAssign => "Bls12831Fp2AddSubAssign",
            Self::Bls12831Fp2MulAssign => "Bls12831Fp2MulAssign",
            Self::Bn254FpOpAssign => "Bn254FpOpAssign",
            Self::Bn254Fp2AddSubAssign => "Bn254Fp2AddSubAssign",
            Self::Bn254Fp2MulAssign => "Bn254Fp2MulAssign",
            Self::Bls12381Decompress => "Bls12381Decompress",
            Self::SyscallCore => "SyscallCore",
            Self::SyscallPrecompile => "SyscallPrecompile",
            Self::DivRem => "DivRem",
            Self::AddSub => "AddSub",
            Self::Bitwise => "Bitwise",
            Self::Mul => "Mul",
            Self::ShiftRight => "ShiftRight",
            Self::ShiftLeft => "ShiftLeft",
            Self::Lt => "Lt",
            Self::CloClz => "CloClz",
            Self::Branch => "Branch",
            Self::Jump => "Jump",
            Self::SyscallInstrs => "SyscallInstrs",
            Self::MemoryInstrs => "MemoryInstrs",
            Self::MiscInstrs => "MiscInstrs",
            Self::MemoryGlobalInit => "MemoryGlobalInit",
            Self::MemoryGlobalFinalize => "MemoryGlobalFinalize",
            Self::MemoryLocal => "MemoryLocal",
            Self::Global => "Global",
            Self::Byte => "Byte",
        }
    }
}

impl FromStr for MipsAirId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let air = Self::iter().find(|chip| chip.as_str() == s);
        match air {
            Some(air) => Ok(air),
            None => Err(format!("Invalid MIPS Air: {s}")),
        }
    }
}

impl Display for MipsAirId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.as_str())
    }
}
