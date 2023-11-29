// A CLI
//
// Input:
//     string to be encrypted
//     <optional> pattern for string functions which require it
//
// Output: Nicely formatted comparison with std::str results.
// the ouptuts will be nicely formatted for the user to see that the results match
// (if there are errors then the bounty would not be considered valid) with timing information for the FHE version.

use clap::Parser;
mod ciphertext;
mod client_key;

use tfhe::{generate_keys, set_server_key, ConfigBuilder, prelude::FheDecrypt, FheUint8};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(name = "fhe_strings")]
#[command(about = "A cli to test the FHE string API.", long_about = None)]
struct Args {
    /// The plain text string
	clear_string: Option<String>,

    /// A pattern to match against the string
	#[arg(short, long)]
    pattern: Option<String>,
}

fn main() {
    let args = Args::parse();
	assert!(!args.clear_string.is_none(), "clear_string required");
	let clear_string = args.clear_string.unwrap();

	let config = ConfigBuilder::default().build();
	let (client_key, server_key) = generate_keys(config);
	let str_client_key = client_key::StringClientKey::new(client_key.clone(), 8_u8);
	let str_nopad_client_key = client_key::StringClientKey::new(client_key.clone(), 0_u8);
	set_server_key(server_key);

	let fhe_string = str_client_key.encrypt(&clear_string);
	let dec_string = str_client_key.decrypt(&fhe_string);
	println!("Start string: '{dec_string}'");


	let fhe_op = fhe_string.trim_start();
	let dec_string = str_client_key.decrypt(&fhe_op);
	println!("Trim start string: '{dec_string}'");

	let mut fhe_op = fhe_string.trim();
	let dec_string = str_client_key.decrypt(&fhe_op);
	println!("Trim: '{dec_string}'");

	let fhe_op = fhe_op.repeat(2);
	let dec_string = str_client_key.decrypt(&fhe_op);
	println!("Repeat: '{dec_string}'");

	// let fhe_string_len = fhe_string.len();
	// let dec_int: u32 = fhe_string_len.decrypt(&client_key);
	// println!("Len string: {dec_string}");
	// assert_eq!(dec_int, clear_string.len() as u32);
	
	// let fhe_is_empty = fhe_string.is_empty();
	// let dec_bool = fhe_is_empty.decrypt(&client_key);
	// println!("Empty string: {dec_bool}");
	// assert_eq!(dec_bool, false);

	// let fhe_empty_string = str_nopad_client_key.encrypt(&"");
	// let fhe_is_empty = fhe_empty_string.is_empty();
	// let dec_bool = fhe_is_empty.decrypt(&client_key);
	// println!("Empty empty string: {dec_bool}");
	// assert_eq!(dec_bool, true);

	// let fhe_string_len = fhe_empty_string.len();
	// let dec_int: u32 = fhe_string_len.decrypt(&client_key);
	// println!("Len empty string: {dec_string}");
	// assert_eq!(dec_int, 0);

	// let fhe_string_upper = fhe_string.to_upper();
	// let dec_string = str_client_key.decrypt(&fhe_string_upper);
	// println!("Upper string: {dec_string}");
	// assert_eq!(dec_string, clear_string.to_uppercase());

	// let fhe_string_lower = fhe_string_upper.to_lower();
	// let dec_string = str_client_key.decrypt(&fhe_string_lower);
	// println!("Lower string: {dec_string}");
	// assert_eq!(dec_string, clear_string.to_lowercase());
    
}
