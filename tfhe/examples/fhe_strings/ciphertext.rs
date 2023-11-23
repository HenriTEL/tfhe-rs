// FheAsciiChar: a wrapper type that will hold a RadixCiphertext from integer which must be able to store at least 8 bits of data to be able to fit a single ASCII char;

// FheString: a wrapper type around a Vec<FheAsciiChar>, the last FheAsciiChar of the string always encrypts a 0u8
// it is possible to have 0u8 earlier than the last char, this would allow the user to hide the actual length of the string that is encrypted

use std::iter;

// accessors should be made to be able to iterate easily on the inner vec both mutably and immutably
// - do not provide a from_blocks primitives as it would be easy to misuse
// - a new function should be enough to construct the type at encryption time with a client key
// see for example tfhe/src/integer/ciphertext/mod.rs to see how Integer RadixCiphertext are built to give access to their content for use by algorithms.
use tfhe::prelude::*;
use tfhe::{ ClientKey, FheUint8};

pub type FheAsciiChar = FheUint8;
pub struct FheString {
    bytes: Vec<FheAsciiChar>,
}

pub const PADDING_BLOCK_LEN: usize = 8;
pub const UP_LOW_DISTANCE: u8 = 32;

impl FheString {
    pub fn encrypt(clear_str: &str, client_key: &ClientKey) -> Self {
        assert!(clear_str.is_ascii(),
            "The input string must only contain ascii characters"
        );
        let nb_zeros = clear_str.len() % PADDING_BLOCK_LEN;

        let fhe_bytes: Vec<FheUint8> = clear_str
            .bytes()
            .chain(iter::repeat(0).take(nb_zeros))
            .map(|byte| FheUint8::encrypt(byte, client_key))
            .take(nb_zeros)
            .collect();

        Self { bytes: fhe_bytes }
    }

    pub fn encrypt_without_padding(clear_str: &str, client_key: &ClientKey) -> Self {
        assert!(clear_str.is_ascii(),
            "The input string must only contain ascii characters"
        );

        let fhe_bytes: Vec<FheUint8> = clear_str
            .bytes()
            .map(|byte| FheUint8::encrypt(byte, client_key))
            .collect();

        Self { bytes: fhe_bytes }
    }

    pub fn decrypt(&self, client_key: &ClientKey) -> String {
        
        let ascii_bytes: Vec<u8> = self.bytes
            .iter()
            .map(|fhe_b| fhe_b.decrypt(client_key))
            .take_while(|b| *b != 0)
            .collect();
        String::from_utf8(ascii_bytes).unwrap()
    }

    pub fn to_upper(&self) -> Self {
        Self {
            bytes: self.bytes.iter().map(to_upper).collect(),
        }
    }

    pub fn to_lower(&self) -> Self {
        Self {
            bytes: self.bytes.iter().map(to_lower).collect(),
        }
    }
}


fn to_upper(c: &FheUint8) -> FheUint8 {
    c - FheUint8::cast_from(c.gt(96) & c.lt(123)) * UP_LOW_DISTANCE
}

fn to_lower(c: &FheUint8) -> FheUint8 {
    c + FheUint8::cast_from(c.gt(64) & c.lt(91)) * UP_LOW_DISTANCE
}
