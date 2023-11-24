// FheAsciiChar: a wrapper type that will hold a RadixCiphertext from integer which must be able to store at least 8 bits of data to be able to fit a single ASCII char;

// FheString: a wrapper type around a Vec<FheAsciiChar>, the last FheAsciiChar of the string always encrypts a 0u8
// it is possible to have 0u8 earlier than the last char, this would allow the user to hide the actual length of the string that is encrypted


// accessors should be made to be able to iterate easily on the inner vec both mutably and immutably
// - do not provide a from_blocks primitives as it would be easy to misuse
// - a new function should be enough to construct the type at encryption time with a client key
// see for example tfhe/src/integer/ciphertext/mod.rs to see how Integer RadixCiphertext are built to give access to their content for use by algorithms.
use tfhe::{prelude::*, FheBool};
use tfhe::{ FheUint8, FheUint32};

pub type FheAsciiChar = FheUint8;
pub struct FheString {
    pub bytes: Vec<FheAsciiChar>,
}

pub const UP_LOW_DISTANCE: u8 = 32;

impl FheString {

    pub fn len(&self) -> FheUint32 {
        let first_byte = self.bytes.first().unwrap();
        let mut res = FheUint32::cast_from(first_byte ^ first_byte); // Init res to 0
        let mut prev_null = first_byte.ne(first_byte); // Init prev_null to false
        for byte in self.bytes.iter() {
            let is_null = byte.eq(0);
            res += FheUint32::cast_from(!(is_null | prev_null));
            prev_null = byte.eq(0);
        }
        res
    }

    pub fn is_empty(&self) -> FheBool {
        let first_byte = self.bytes.first().unwrap();
        FheUint8::eq(first_byte, 0)
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
