use crate::syscall_poseidon2_permute;

const WIDTH: usize = 16; // Number of field elements in the Poseidon2 state
const RATE: usize = 8; // Number of field elements processed per round
const OUT: usize = 8; // Number of field elements in the output
const FIELD_SIZE: usize = 3; // Number of bytes can be safely converted to field element

/// Executes the Poseidon2 permutation on the given state
pub fn poseidon2_permute(state: &mut [u32; WIDTH]) {
    unsafe {
        syscall_poseidon2_permute(state);
    }
}

/// Perform the Poseidon2 hash on the given input
pub fn poseidon2(input: &[u8]) -> [u8; 32] {
    let l = input.len();
    let mut padded_input = input.to_vec();
    let new_size = (l + FIELD_SIZE) / FIELD_SIZE * FIELD_SIZE;
    padded_input.resize(new_size, 0);

    // Pad the input to a multiple of 3 bytes
    // Pad 1*01
    if l % FIELD_SIZE == FIELD_SIZE - 1 {
        padded_input[l] = 0b10000001;
    } else {
        padded_input[l] = 1;
        padded_input[new_size - 1] = 0b10000000;
    }
    let field_input = bytes_to_field_elements(&padded_input);

    let mut state = [0u32; WIDTH];
    let mut chunks = field_input.chunks_exact(RATE);

    for chunk in &mut chunks {
        state[..RATE].clone_from_slice(chunk);
        unsafe {
            syscall_poseidon2_permute(&mut state);
        }
    }

    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        state[..remainder.len()].clone_from_slice(remainder);
        unsafe {
            syscall_poseidon2_permute(&mut state);
        }
    }

    let result =
        state.into_iter().take(OUT).map(|x| x.to_le_bytes()).flatten().collect::<Vec<u8>>();

    result.try_into().unwrap()
}

// each 3 bytes of input can be safely converted to a field element
#[inline]
fn bytes_to_field_elements(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks(3)
        .map(|chunk| {
            let mut value = 0u32;
            for (i, &byte) in chunk.iter().enumerate() {
                value |= (byte as u32) << (i * 8);
            }
            value
        })
        .collect()
}
