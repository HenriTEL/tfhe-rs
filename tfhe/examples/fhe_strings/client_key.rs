use std::iter;

use concrete_csprng::seeders::Seed;

use tfhe::{prelude::*, FheUint8, ClientKey, Config};

use crate::ciphertext::FheString;
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
		let nb_zeros = match self.padding {
			0 => clear_str.is_empty() as usize, // Empty non-padded strings are represented as ['\0']
			_ => clear_str.len() % self.padding as usize,
		};
        let fhe_bytes: Vec<FheUint8> = clear_str
            .bytes()
            .chain(iter::repeat(0).take(nb_zeros))
            .map(|byte| FheUint8::encrypt(byte, &self.key))
            .collect();

		FheString { bytes: fhe_bytes }
    }

    // TODO check the use of &FheString instead of FheString
	pub fn decrypt(&self, fhe_string: &FheString) -> String {
        let ascii_bytes: Vec<u8> = fhe_string.bytes
            .iter()
            .map(|fhe_byte| fhe_byte.decrypt(&self.key))
            .take_while(|byte| *byte != 0)
            .collect();
        String::from_utf8(ascii_bytes).unwrap()
    }
}
