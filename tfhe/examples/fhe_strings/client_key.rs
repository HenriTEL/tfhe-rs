use std::iter;

use tfhe::prelude::*;
use tfhe::ClientKey;

use crate::ciphertext::{FheAsciiChar, FheString, Padding};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StringClientKey {
    pub key: ClientKey,
    padding: usize,
}

impl StringClientKey {
    pub fn new(key: ClientKey, padding: usize) -> Self {
        Self { key, padding }
    }
    pub fn encrypt(&self, clear_str: &str) -> FheString {
        assert!(
            clear_str.is_ascii(),
            "The input string must only contain ascii characters"
        );
        assert!(
            !clear_str.trim_end_matches('\0').contains('\0'),
            "The input string can only contain '\\0's at its end."
        );

        let already_padded = clear_str.contains('\0');
        let required_zeros = match self.padding {
            0 => 0,
            _ => {
                if already_padded {
                    0
                } else if clear_str.len() >= self.padding {
                    clear_str.len() % self.padding
                } else {
                    self.padding - clear_str.len()
                }
            }
        };
        let chars: Vec<FheAsciiChar> = clear_str
            .as_bytes()
            .iter()
            .chain(iter::repeat(&0_u8).take(required_zeros))
            .map(|byte| FheAsciiChar::encrypt(*byte, &self.key))
            .collect();
        let padding = *Padding::default().end(already_padded || self.padding > 0);

        FheString { chars, padding }
    }

    pub fn decrypt(&self, fhe_string: &FheString) -> String {
        let ascii_bytes: Vec<u8> = fhe_string
            .chars
            .iter()
            .map(|fhe_byte| fhe_byte.byte.decrypt(&self.key))
            .filter(|byte| *byte != 0)
            .collect();
        String::from_utf8(ascii_bytes).unwrap()
    }
}
