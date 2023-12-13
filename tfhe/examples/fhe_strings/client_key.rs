use std::iter;

use concrete_csprng::seeders::Seed;

use log::info;
use tfhe::{prelude::*, ClientKey, Config};

use crate::ciphertext::{FheString, FheAsciiChar, PaddingOptions};
// use keys::{IntegerClientKey, IntegerConfig};
// use tfhe::integers::keys::IntegerConfig;
// use tfhe::keys::IntegerClientKey;
// use tfhe::integers::{IntegerClientKey, IntegerConfig};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StringClientKey {
	key: ClientKey,
	padding: u8,
}

impl StringClientKey {
	pub fn new(key: ClientKey, padding: u8) -> Self {
		Self { key, padding }
	}
	pub fn with_seed(config: Config, seed: Seed, padding: u8) -> Self {
        Self {
			key: ClientKey::generate_with_seed(config, seed),
			padding,
		}
    }
    pub fn encrypt(&self, clear_str: &str) -> FheString {
        assert!(clear_str.is_ascii(),
            "The input string must only contain ascii characters"
        );
        // '\0' is reseved to express an empty character slot
        assert!(!clear_str.contains('\0'),
            "The input string must not contain the NUL character '\\0'"
        );  
		let nb_zeros = match self.padding {
			0 => clear_str.is_empty() as usize, // Empty non-padded strings are represented as ['\0']
			_ => if clear_str.len() >= self.padding as usize {
                    clear_str.len() % self.padding as usize
                } else {
                    self.padding as usize - clear_str.len()
                }
		};
        info!("Adding {nb_zeros} zeros.");
        let chars: Vec<FheAsciiChar> = clear_str
            .bytes()
            .chain(iter::repeat(0).take(nb_zeros))
            .map(|byte| FheAsciiChar::encrypt(byte, &self.key))
            .collect();
        let mut padding = PaddingOptions::default();
        padding.end(self.padding > 0);

		FheString { chars, padding }
    }

    // TODO check the use of &FheString instead of FheString
	pub fn decrypt(&self, fhe_string: &FheString) -> String {
        let ascii_bytes: Vec<u8> = fhe_string.chars
            .iter()
            .map(|fhe_byte| fhe_byte.byte.decrypt(&self.key))
            .filter(|byte| *byte != 0)
            .collect();
        String::from_utf8(ascii_bytes).unwrap()
    }
}
