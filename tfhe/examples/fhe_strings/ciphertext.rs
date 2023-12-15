// FheAsciiChar: a wrapper type that will hold a RadixCiphertext from integer which must be able to store at least 8 bits of data to be able to fit a single ASCII char;

// FheString: a wrapper type around a Vec<FheAsciiChar>, the last FheAsciiChar of the string always encrypts a 0u8
// it is possible to have 0u8 earlier than the last char, this would allow the user to hide the actual length of the string that is encrypted

// accessors should be made to be able to iterate easily on the inner vec both mutably and immutably
// - do not provide a from_blocks primitives as it would be easy to misuse
// - a new function should be enough to construct the type at encryption time with a client key
// see for example tfhe/src/integer/ciphertext/mod.rs to see how Integer RadixCiphertext are built to give access to their content for use by algorithms.
use tfhe::{prelude::*, FheBool, ClientKey};
use tfhe::{ FheUint8, FheUint32};

use crate::pattern_matcher::{SimpleEngine, Pattern, MatchingOptions};

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

#[derive(Default, Debug, Copy, Clone)]
pub struct PaddingOptions {
    pub start: bool,
    pub middle: bool,
    pub end: bool,
}

impl PaddingOptions {
    // Methods to set individual flags
    pub fn start(&mut self, value: bool) -> &mut Self {
        self.start = value;
        self
    }

    pub fn middle(&mut self, value: bool) -> &mut Self {
        self.middle = value;
        self
    }

    pub fn end(&mut self, value: bool) -> &mut Self {
        self.end = value;
        self
    }
}

#[derive(Clone)]
pub struct FheString {
    pub chars: Vec<FheAsciiChar>,
    pub padding: PaddingOptions,
}

impl FheString {

    pub fn has_padding(&self) -> bool {
        self.padding.start | self.padding.middle | self.padding.end
    }

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
            padding: self.padding,
        }
    }

    pub fn to_lower(&self) -> Self {
        Self {
            chars: self.chars.iter()
                    .map(|c| c.to_lower())
                    .collect(),
            padding: self.padding,
        }
    }

    // TODO merge common parts with trim_start()
    pub fn trim_end(&self) -> Self {
        let new_bytes = self.trim_chars(self.chars.iter().rev());

        Self {
            chars: new_bytes.iter().rev()
                        .map(|b|FheAsciiChar { byte: b.to_owned() })
                        .collect(),
            padding: *self.padding.clone().start(true),
        } 
    }

    pub fn trim_start(&self) -> Self {
        let new_bytes = self.trim_chars(self.chars.iter());

        Self {
            chars: new_bytes.iter()
                        .map(|b|FheAsciiChar { byte: b.to_owned() })
                        .collect(),
            padding: *self.padding.clone().start(true),
        } 
    }

    pub fn trim(&self) -> Self {
        self.trim_end().trim_start()
    }

    // We build a vector with a lenght of the maximum possible repetitions.
    // Characters of string repetitions that goes beyond n are nullified.
    pub fn repeat(&self, n: FheUint8) -> Self {
        let mut new_chars: Vec<FheAsciiChar> = vec![];
        let mut rem = n.clone();
        // TODO loop until u8::MAX
        for _ in 0..8 {
            let operand = FheUint8::cast_from(rem.gt(0));
            // TODO I assume that clone() is cryptographically safe here, i.e. not a bit to bit clone
            new_chars.extend(self.chars.clone().iter().map(|c| FheAsciiChar { byte: c.byte.to_owned() * &operand }));
            rem = rem.clone() - FheUint8::cast_from(rem.gt(0));
        }

        Self {
            chars: new_chars,
            padding: *self.padding.clone().middle(self.padding.start | self.padding.end),
        }
    }

    pub fn contains(&self, pattern: FheString) -> FheBool {
        let mut se = SimpleEngine::new();
        let match_options = MatchingOptions::default();
        let match_pattern = Pattern::Encrypted(pattern);
        se.has_match(self, &match_pattern, match_options)
    }

    pub fn starts_with(&self, pattern: FheString) -> FheBool {
        let mut se = SimpleEngine::new();
        let match_options = MatchingOptions { sof: true, eof: false };
        let match_pattern = Pattern::Encrypted(pattern);
        se.has_match(self, &match_pattern, match_options)
    }

    pub fn ends_with(&self, pattern: FheString) -> FheBool {
        let mut se = SimpleEngine::new();
        let match_options = MatchingOptions { sof: false, eof: true };
        let match_pattern = Pattern::Encrypted(pattern);
        se.has_match(self, &match_pattern, match_options)
    }

    pub fn eq(&self, other: Self) -> FheBool {
        let mut se = SimpleEngine::new();
        let match_options = MatchingOptions { sof: true, eof: true };
        let match_pattern = Pattern::Encrypted(other);
        se.has_match(self, &match_pattern, match_options)
    }

    pub fn ne(&self, other: Self) -> FheBool {
        !self.eq(other)
    }

    pub fn eq_ignore_case(&self, other: Self) -> FheBool {
        self.to_lower().eq(other.to_lower())
    }

    pub fn repeat_clear(&self, n: usize) -> Self {
        let mut new_chars: Vec<FheAsciiChar> = vec![];
        for _ in 0..n {
            new_chars.extend(self.chars.clone())
        }

        Self {
            chars: new_chars,
            padding: *self.padding.clone().middle(n > 0 && (self.padding.start | self.padding.end)),
        }
    }

    pub fn contains_clear(&self, pattern: &str) -> FheBool {
        let mut se = SimpleEngine::new();
        let match_options = MatchingOptions::default();
        let match_pattern = Pattern::Clear(pattern.to_string());
        se.has_match(self, &match_pattern, match_options)
    }

    pub fn starts_with_clear(&self, pattern: &str) -> FheBool {
        let mut se = SimpleEngine::new();
        let match_options = MatchingOptions { sof: true, eof: false };
        let match_pattern = Pattern::Clear(pattern.to_string());
        se.has_match(self, &match_pattern, match_options)
    }

    pub fn ends_with_clear(&self, pattern: &str) -> FheBool {
        let mut se = SimpleEngine::new();
        let match_options = MatchingOptions { sof: false, eof: true };
        let match_pattern = Pattern::Clear(pattern.to_string());
        se.has_match(self, &match_pattern, match_options)
    }

    fn trim_chars<'a>(&self, iter: impl Iterator<Item = &'a FheAsciiChar>) -> Vec<FheUint8> {
        let mut new_bytes: Vec<FheUint8> = vec![];
        let fhe_max_u8 = FheUint8::encrypt_trivial(u8::MAX);
        let mut prev_whitespace = FheBool::try_encrypt_trivial(true).unwrap();
        for c in iter {
            let must_zero =  prev_whitespace.clone() & (c.is_whitespace() | c.byte.eq(0));
            let new_byte = c.byte.to_owned() & (FheUint8::cast_from(!must_zero) * &fhe_max_u8);
            new_bytes.push(new_byte);
            prev_whitespace = prev_whitespace & (c.is_whitespace() | c.byte.eq(0));
        }

        new_bytes
    }
}


impl std::ops::Add for FheString {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let mut chars: Vec<FheAsciiChar> = vec![];
        chars.extend(self.chars.clone());
        chars.extend(other.chars.clone());
        let padding: PaddingOptions = *PaddingOptions::default()
        .start(self.padding.start)
        .middle(self.padding.middle | self.padding.end | other.padding.start | other.padding.middle)
        .end(other.padding.end);

        Self {
            chars,
            padding,
        }
    }
}

// impl PartialOrd for FheString {
//     fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
//         self.value.partial_cmp(&other.value)
//     }
// }
