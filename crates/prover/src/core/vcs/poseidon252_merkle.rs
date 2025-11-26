#![allow(unused)]
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use starknet_crypto::{poseidon_hash, poseidon_hash_many};
use starknet_ff::FieldElement as FieldElement252;

use super::ops::MerkleHasher;
use crate::core::channel::{MerkleChannel, Poseidon252Channel};
use crate::core::fields::m31::{BaseField, M31};
use crate::core::vcs::hash::Hash;

const ELEMENTS_IN_BLOCK: usize = 8;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct Poseidon252MerkleHasher;
impl MerkleHasher for Poseidon252MerkleHasher {
    type Hash = FieldElement252;

    fn hash_node(
        children_hashes: Option<(Self::Hash, Self::Hash)>,
        column_values: &[BaseField],
    ) -> Self::Hash {
        let n_column_blocks = column_values.len().div_ceil(ELEMENTS_IN_BLOCK);
        let values_len = 2 + n_column_blocks;
        let mut values = Vec::with_capacity(values_len);

        if let Some((left, right)) = children_hashes {
            values.push(left);
            values.push(right);
        }

        let padding_length = ELEMENTS_IN_BLOCK * n_column_blocks - column_values.len();
        let padded_values = column_values
            .iter()
            .copied()
            .chain(std::iter::repeat_n(BaseField::zero(), padding_length));
        for chunk in padded_values.array_chunks::<ELEMENTS_IN_BLOCK>() {
            values.push(construct_felt252_from_m31s(&chunk));
        }
        poseidon_hash_many(&values)
    }
}

fn construct_felt252_from_m31s(word: &[M31; 8]) -> FieldElement252 {
    // Felt = Felt << 31 + limb.
    let append_m31 = |felt: &mut [u128; 2], limb: M31| {
        *felt = [
            felt[0] << 31 | limb.0 as u128,
            felt[0] >> (128 - 31) | felt[1] << 31,
        ];
    };

    let mut felt_as_u256 = [0u128; 2];
    for limb in word {
        append_m31(&mut felt_as_u256, *limb);
    }

    let felt_bytes = [felt_as_u256[1].to_be_bytes(), felt_as_u256[0].to_be_bytes()];
    let felt_bytes = unsafe { std::mem::transmute::<[[u8; 16]; 2], [u8; 32]>(felt_bytes) };
    FieldElement252::from_bytes_be(&felt_bytes).unwrap()
}

impl Hash for FieldElement252 {}

#[derive(Default)]
pub struct Poseidon252MerkleChannel;

impl MerkleChannel for Poseidon252MerkleChannel {
    type C = Poseidon252Channel;
    type H = Poseidon252MerkleHasher;

    fn mix_root(channel: &mut Self::C, root: <Self::H as MerkleHasher>::Hash) {
        channel.update_digest(poseidon_hash(channel.digest(), root));
    }
}
