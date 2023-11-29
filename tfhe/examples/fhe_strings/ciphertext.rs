// FheAsciiChar: a wrapper type that will hold a RadixCiphertext from integer which must be able to store at least 8 bits of data to be able to fit a single ASCII char;

// FheString: a wrapper type around a Vec<FheAsciiChar>, the last FheAsciiChar of the string always encrypts a 0u8
// it is possible to have 0u8 earlier than the last char, this would allow the user to hide the actual length of the string that is encrypted


// accessors should be made to be able to iterate easily on the inner vec both mutably and immutably
// - do not provide a from_blocks primitives as it would be easy to misuse
// - a new function should be enough to construct the type at encryption time with a client key
// see for example tfhe/src/integer/ciphertext/mod.rs to see how Integer RadixCiphertext are built to give access to their content for use by algorithms.
use tfhe::{prelude::*, FheBool, ClientKey};
use tfhe::{ FheUint8, FheUint32};

pub const ASCII_WHITESPACES:  [u8; 5] = [9, 10, 11, 13, 32]; // Tab, Newline, Vertical Tab, Carriage Return, Space
pub const UP_LOW_DISTANCE: u8 = 32;

#[derive(Clone)]
pub struct FheAsciiChar {
    pub byte: FheUint8,
}

impl FheAsciiChar {

	pub fn encrypt(clear_byte: u8, key: &ClientKey) -> Self {
		Self { byte: FheUint8::encrypt(clear_byte, key) }
	}

    pub fn is_whitespace(&self) -> FheBool {
        ASCII_WHITESPACES.iter()
            .map(|w| self.byte.eq(*w))
            .reduce(|acc, e| acc | e)
            .unwrap()
    }

    pub fn eq(&self , rhs: Self) -> FheBool {
        self.byte.eq(&rhs.byte)
    }

    pub fn ne(&self , rhs: Self) -> FheBool {
        self.byte.ne(&rhs.byte)
    }

    fn to_upper(&self) -> Self {
        Self {
            byte: &self.byte - FheUint8::cast_from(self.byte.gt(96) & self.byte.lt(123)) * UP_LOW_DISTANCE
        }
    }
    
    fn to_lower(&self) -> Self {
        Self {
            byte: &self.byte + FheUint8::cast_from(self.byte.gt(64) & self.byte.lt(91)) * UP_LOW_DISTANCE
        }
    }

}


impl CastFrom<FheAsciiChar> for FheUint32
{
    fn cast_from(input: FheAsciiChar) -> Self {
        Self::cast_from(input.byte)
    }
}

pub struct FheString {
    pub chars: Vec<FheAsciiChar>,
}

impl FheString {

    pub fn len(&self) -> FheUint32 {
        let mut res = FheUint32::encrypt_trivial(0);
        let mut prev_null = FheBool::encrypt_trivial(false);
        for char in self.chars.iter() {
            let is_null = char.byte.eq(0);
            res += FheUint32::cast_from(!(is_null | prev_null));
            prev_null = char.byte.eq(0);
        }
        res
    }

    pub fn is_empty(&self) -> FheBool {
        let first_byte = self.chars.first().unwrap();
        FheUint8::eq(&first_byte.byte, 0)
    }

    pub fn to_upper(&self) -> Self {
        Self {
            chars: self.chars.iter().map(|c| c.to_upper()).collect(),
        }
    }

    pub fn to_lower(&self) -> Self {
        Self {
            chars: self.chars.iter()
                    .map(|c| c.to_lower())
                    .collect(),
        }
    }

    // TODO merge common parts with trim_start()
    pub fn trim_end(&self) -> Self {
        let mut new_bytes: Vec<FheUint8> = vec![];
        let fhe_255 = FheUint8::try_encrypt_trivial(255_u8).unwrap();
        let mut prev_whitespace = FheBool::try_encrypt_trivial(true).unwrap();
        for c in self.chars.iter().rev() {
            let must_zero =  prev_whitespace.clone() & c.is_whitespace();
            let new_byte = c.byte.to_owned() & (FheUint8::cast_from(!must_zero) * &fhe_255);
            new_bytes.push(new_byte);
            prev_whitespace = prev_whitespace & c.is_whitespace();
        }

        Self {
            chars: new_bytes.iter()
                        .rev()
                        .map(|b|FheAsciiChar { byte: b.to_owned() })
                        .collect()
        }
    }

    pub fn trim_start(&self) -> Self {
        let mut new_bytes: Vec<FheUint8> = vec![];
        let fhe_255 = FheUint8::try_encrypt_trivial(255_u8).unwrap();
        let mut prev_whitespace = FheBool::try_encrypt_trivial(true).unwrap();
        for c in self.chars.iter() {
            let must_zero =  prev_whitespace.clone() & c.is_whitespace();
            let new_byte = c.byte.to_owned() & (FheUint8::cast_from(!must_zero) * &fhe_255);
            new_bytes.push(new_byte);
            prev_whitespace = prev_whitespace & c.is_whitespace();
        }

        Self {
            chars: new_bytes.iter()
                        .map(|b|FheAsciiChar { byte: b.to_owned() })
                        .collect()
        }
        
    }

    pub fn trim(&self) -> Self {
        self.trim_end().trim_start()
    }

    pub fn repeat_clear_n(&self, n: usize) -> Self {
        let mut new_chars: Vec<FheAsciiChar> = vec![];
        for _ in 0..n {
            // TODO I assume that clone() is cryptographically safe here, i.e. not a bit to bit clone
            new_chars.extend(self.chars.clone())
        }
        Self {
            chars: new_chars
        }
    }

}