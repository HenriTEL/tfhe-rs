use rayon::prelude::*;

use tfhe::prelude::*;
use tfhe::{ClientKey, FheBool, FheInt16, FheUint16, FheUint8};

use crate::pattern_matcher::{MatchingOptions, Pattern, SimpleEngine, MatchResult};

const ASCII_WHITESPACES: [u8; 5] = [9, 10, 11, 13, 32]; // Tab, Newline, Vertical Tab, Carriage Return, Space
const UP_LOW_DISTANCE: u8 = 32;

#[derive(Clone)]
pub struct FheString {
    pub chars: Vec<FheAsciiChar>,
    pub padding: PaddingOptions,
}

impl FheString {
    pub fn has_padding(&self) -> bool {
        self.padding.start | self.padding.middle | self.padding.end
    }

    pub fn len(&self) -> FheUint16 {
        let mut res = FheUint16::encrypt_trivial(0);
        for char in self.chars.iter() {
            res += FheUint16::cast_from(char.byte.ne(0));
        }

        res
    }

    pub fn is_empty(&self) -> FheBool {
        if self.chars.is_empty() {
            return FheBool::encrypt_trivial(true);
        }
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
            chars: self.chars.iter().map(|c| c.to_lower()).collect(),
            padding: self.padding,
        }
    }

    pub fn trim_start(&self) -> Self {
        let new_bytes = self.trim_chars(self.chars.iter());

        Self {
            chars: new_bytes
                .iter()
                .map(|b| FheAsciiChar { byte: b.to_owned() })
                .collect(),
            padding: *self.padding.clone().start(true),
        }
    }

    pub fn trim_end(&self) -> Self {
        let new_bytes = self.trim_chars(self.chars.iter().rev());

        Self {
            chars: new_bytes
                .iter()
                .rev()
                .map(|b| FheAsciiChar { byte: b.to_owned() })
                .collect(),
            padding: *self.padding.clone().start(true),
        }
    }

    pub fn trim(&self) -> Self {
        self.trim_start().trim_end()
    }

    // We build a vector with a lenght of the maximum possible repetitions.
    // Characters of string repetitions that goes beyond n are nullified.
    // The default max num of reptition in u8::MAX = 255 which is quite expensive.
    // To mitigate this, we pass a MaxedFheUint8 instead of FheUint8 directly,
    // that way we can considerably reduce the number of computations while only providing
    // a range of [0..max_val] values as a hint to the actual number of repetitions.
    //
    // A note about padding:
    // This function can introduce zeros somewhere in the middle of the string
    // if the original string had zeros at the beginning (when trim or trim_start was applied) or
    // the end of it.
    pub fn repeat(&self, n: MaxedFheUint8) -> Self {
        let mut new_chars: Vec<FheAsciiChar> = vec![];
        let mut rem = n.val.clone();
        for _ in 0..n.max_val {
            let operand = FheUint8::cast_from(rem.gt(0));
            // TODO I assume that clone() is cryptographically safe here, i.e. not a bit to bit
            // clone
            new_chars.extend(self.chars.clone().iter().map(|c| FheAsciiChar {
                byte: c.byte.to_owned() * &operand,
            }));
            rem = rem.clone() - FheUint8::cast_from(rem.gt(0));
        }

        Self {
            chars: new_chars,
            padding: *self
                .padding
                .clone()
                .middle(self.padding.start | self.padding.end),
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
        let match_options = MatchingOptions {
            sof: true,
            eof: false,
            result: MatchResult::Bool,
        };
        let match_pattern = Pattern::Encrypted(pattern);
        se.has_match(self, &match_pattern, match_options)
    }

    pub fn ends_with(&self, pattern: FheString) -> FheBool {
        let mut se = SimpleEngine::new();
        let match_options = MatchingOptions {
            sof: false,
            eof: true,
            result: MatchResult::Bool,
        };
        let match_pattern = Pattern::Encrypted(pattern);
        se.has_match(self, &match_pattern, match_options)
    }

    pub fn eq(&self, other: Self) -> FheBool {
        let mut se = SimpleEngine::new();
        let match_options = MatchingOptions {
            sof: true,
            eof: true,
            result: MatchResult::Bool,
        };
        let match_pattern = Pattern::Encrypted(other);
        se.has_match(self, &match_pattern, match_options)
    }

    pub fn ne(&self, other: Self) -> FheBool {
        !self.eq(other)
    }

    pub fn eq_ignore_case(&self, other: Self) -> FheBool {
        self.to_lower().eq(other.to_lower())
    }

    pub fn find(&self, pattern: FheString) -> FheInt16 {
        let mut se = SimpleEngine::new();
        let match_options = MatchingOptions {
            sof: false,
            eof: false,
            result: MatchResult::StartIndex,
        };
        let match_pattern = Pattern::Encrypted(pattern);
        se.find(self, &match_pattern, match_options)
    }

    pub fn rfind(&self, pattern: FheString) -> FheInt16 {
        let rev_s = self.reversed();
        let rev_find = rev_s.find(pattern.reversed());
        let s_len = FheInt16::cast_from(self.len());
        let p_len = FheInt16::encrypt_trivial(pattern.chars.len() as i16);
        
        FheInt16::cast_from(rev_find.gt(-1)) * (s_len - p_len - rev_find + 1) - 1
    }

    pub fn strip_prefix(&self, pattern: FheString) -> Self {
        let fhe_max_u8 = FheUint8::encrypt_trivial(u8::MAX);
        let mut se = SimpleEngine::new();
        let match_options = MatchingOptions {
            sof: false,
            eof: false,
            result: MatchResult::RawStartIndex,
        };
        // TODO find a way to remove .clone() calls
        let match_pattern = Pattern::Encrypted(pattern.clone());
        let prefix_raw_index = se.find(self, &match_pattern, match_options);
        let found_prefix = self.starts_with(pattern.clone());
        let end_index = prefix_raw_index + FheInt16::encrypt_trivial(pattern.chars.len() as i16 - 1);

        Self {
            chars: self
                .chars
                .par_iter()
                .enumerate()
                .map(|(i, c)| {
                    let must_zero = found_prefix.clone() & end_index.ge(i as i16);
                    c.byte.to_owned() & (FheUint8::cast_from(!must_zero) * &fhe_max_u8)
                })
                .map(|b| FheAsciiChar { byte: b.to_owned() })
                .collect(),
            padding: *self.padding.clone().start(true),
        }
    }

    // TODO merge duplicate code with strip_prefix
    pub fn strip_suffix(&self, pattern: FheString) -> Self {
        let fhe_max_u8 = FheUint8::encrypt_trivial(u8::MAX);
        let rev_s = self.reversed();
        let mut se = SimpleEngine::new();
        let match_options = MatchingOptions {
            sof: false,
            eof: false,
            result: MatchResult::RawStartIndex,
        };
        let match_pattern = Pattern::Encrypted(pattern.reversed());
        let rev_find = se.find(&rev_s, &match_pattern, match_options);
        let s_len = FheInt16::encrypt_trivial(self.chars.len() as i16);
        let p_len = FheInt16::encrypt_trivial(pattern.chars.len() as i16);

        let suffix_raw_index = s_len - p_len - rev_find;
        let found_suffix = self.ends_with(pattern.clone());

        Self {
            chars: self
                .chars
                .par_iter()
                .enumerate()
                .map(|(i, c)| {
                    let must_zero = found_suffix.clone() & suffix_raw_index.le(i as i16);
                    c.byte.to_owned() & (FheUint8::cast_from(!must_zero) * &fhe_max_u8)
                })
                .map(|b| FheAsciiChar { byte: b.to_owned() })
                .collect(),
            padding: *self.padding.clone().end(true),
        }
    }
    // ----------------------------------------------------------
    // Functions with clear parameters
    // ----------------------------------------------------------

    pub fn repeat_clear(&self, n: usize) -> Self {
        let mut new_chars: Vec<FheAsciiChar> = vec![];
        for _ in 0..n {
            new_chars.extend(self.chars.clone())
        }

        Self {
            chars: new_chars,
            padding: *self
                .padding
                .clone()
                .middle(n > 0 && (self.padding.start | self.padding.end)),
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
        let match_options = MatchingOptions {
            sof: true,
            eof: false,
            result: MatchResult::Bool,
        };
        let match_pattern = Pattern::Clear(pattern.to_string());
        se.has_match(self, &match_pattern, match_options)
    }

    pub fn ends_with_clear(&self, pattern: &str) -> FheBool {
        let mut se = SimpleEngine::new();
        let match_options = MatchingOptions {
            sof: false,
            eof: true,
            result: MatchResult::Bool,
        };
        let match_pattern = Pattern::Clear(pattern.to_string());
        se.has_match(self, &match_pattern, match_options)
    }

    //
    // Private functions
    //

    fn trim_chars<'a>(&self, iter: impl Iterator<Item = &'a FheAsciiChar>) -> Vec<FheUint8> {
        let mut new_bytes: Vec<FheUint8> = vec![];
        let fhe_max_u8 = FheUint8::encrypt_trivial(u8::MAX);
        let mut prev_zeroed = FheBool::try_encrypt_trivial(true).unwrap();
        for c in iter {
            let must_zero = prev_zeroed.clone() & (c.is_whitespace() | c.byte.eq(0));
            let new_byte =
                c.byte.to_owned() & (FheUint8::cast_from(!must_zero.clone()) * &fhe_max_u8);
            new_bytes.push(new_byte);
            prev_zeroed = must_zero;
        }

        new_bytes
    }

    fn reversed(&self) -> Self {
        Self {
            chars: self.chars.iter().rev().cloned().collect(),
            padding: PaddingOptions {
                start: self.padding.end,
                middle: self.padding.middle,
                end: self.padding.start,
            }
        }
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
            .middle(
                self.padding.middle | self.padding.end | other.padding.start | other.padding.middle,
            )
            .end(other.padding.end);

        Self { chars, padding }
    }
}

// impl PartialOrd for FheString {
//     fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
//         self.value.partial_cmp(&other.value)
//     }
// }
#[derive(Clone)]
pub struct FheAsciiChar {
    pub byte: FheUint8,
}

impl FheAsciiChar {
    pub fn encrypt(clear_byte: u8, key: &ClientKey) -> Self {
        Self {
            byte: FheUint8::encrypt(clear_byte, key),
        }
    }

    pub fn is_whitespace(&self) -> FheBool {
        ASCII_WHITESPACES
            .iter()
            .map(|w| self.byte.eq(*w))
            .reduce(|acc, e| acc | e)
            .unwrap()
    }

    pub fn eq(&self, rhs: Self) -> FheBool {
        self.byte.eq(&rhs.byte)
    }

    pub fn ne(&self, rhs: Self) -> FheBool {
        self.byte.ne(&rhs.byte)
    }

    fn to_upper(&self) -> Self {
        Self {
            byte: &self.byte
                - FheUint8::cast_from(self.byte.gt(96) & self.byte.lt(123)) * UP_LOW_DISTANCE,
        }
    }

    fn to_lower(&self) -> Self {
        Self {
            byte: &self.byte
                + FheUint8::cast_from(self.byte.gt(64) & self.byte.lt(91)) * UP_LOW_DISTANCE,
        }
    }
}

// impl CastFrom<FheAsciiChar> for FheUint32 {
//     fn cast_from(input: FheAsciiChar) -> Self {
//         Self::cast_from(input.byte)
//     }
// }

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

pub struct MaxedFheUint8 {
    pub val: FheUint8,
    pub max_val: u8,
}
