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

use tfhe::{generate_keys, set_server_key, ConfigBuilder, prelude::FheDecrypt};

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
	set_server_key(server_key);

	let fhe_string = ciphertext::FheString::encrypt(&clear_string, &client_key);
	let dec_string = fhe_string.decrypt(&client_key);
	println!("Start string: {dec_string}");

	let fhe_string_len = fhe_string.len();
	let dec_int: u32 = fhe_string_len.decrypt(&client_key);
	println!("Len string: {dec_string}");
	assert_eq!(dec_int, 4);

	
	let fhe_is_empty = fhe_string.is_empty();
	let dec_bool = fhe_is_empty.decrypt(&client_key);
	println!("Empty string: {dec_bool}");
	assert_eq!(dec_bool, false);


	let fhe_empty_string = ciphertext::FheString::encrypt_without_padding(&"", &client_key);
	let fhe_is_empty = fhe_empty_string.is_empty();
	let dec_bool = fhe_is_empty.decrypt(&client_key);
	println!("Empty empty string: {dec_bool}");
	assert_eq!(dec_bool, true);

	let fhe_string_len = fhe_empty_string.len();
	let dec_int: u32 = fhe_string_len.decrypt(&client_key);
	println!("Len empty string: {dec_string}");
	assert_eq!(dec_int, 0);

	let fhe_string_upper = fhe_string.to_upper();
	let dec_string = fhe_string_upper.decrypt(&client_key);
	println!("Upper string: {dec_string}");
	assert_eq!(dec_string, "ELO?");

	let fhe_string_lower = fhe_string_upper.to_lower();
	let dec_string = fhe_string_lower.decrypt(&client_key);
	println!("Lower string: {dec_string}");
	assert_eq!(dec_string, "elo?");
    
}
