# TFHE String Bounty

For this bounty I used higher-level `FheUint8` instead of  `RadixCiphertexts` for simplicity, as I wanted to get a working version for all functions ASAP and only think about compliance and optimizations in a second time. I also adapted the regex engine code to work on `FheUint8` and the performance drop was not huge.  
I implemented a significant part of the functions but I'm getting out of time for the remaining ones.  

Regarding performance optimization, most of the time was spent on pattern matching/finding function. I find it quite performant and it optimizes well depending on the padding position, or when there is no padding at all.  
There are still many low hanging fruits to improve performance on most functions.  

One thing I'm happy with is that all implemented functions should chain well. To make this work I had to handle strings that can have padding zeroes at the start, middle or end. Padding at the start can happen after a call to `trim` or `trim_start` while padding in the middle happens after a call to `repeat`.  

Other than that, most of my algorithms are not complex. I used common techniques of SIMD and GPU programming. For example by taking advantage of the multiplication's absorbing element `x * 0 = 0` to discard characters.

You can run the main as follow: `cargo run -r --example fhe_strings -- " cou " 'ou'`.