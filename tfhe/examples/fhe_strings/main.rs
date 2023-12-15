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
mod pattern_matcher;

use env_logger::Env;
use log::info;
use tfhe::{prelude::*, ClientKey, Config};
use tfhe::{set_server_key, ConfigBuilder, FheUint8};

#[derive(Parser, Debug)]
#[command(name = "fhe_strings")]
#[command(about = "A cli to test the FHE string API.", long_about = None)]
struct Args {
    /// The plain text string
	clear_string: Option<String>,

    /// A pattern to match against the string
    pattern: Option<String>,
}

fn main() {
    let env = Env::default().filter_or("RUST_LOG", "info");
    env_logger::init_from_env(env);
	info!("Start main");
    let args = Args::parse();
	assert!(!args.clear_string.is_none(), "clear_string required");
	let clear_string = args.clear_string.unwrap();

	let config = ConfigBuilder::default().build();
	let client_key = gen_server_keys_for_threads(config, 1);

	let str_client_key = client_key::StringClientKey::new(client_key.clone(), 4_u8);
	let str_nopad_client_key = client_key::StringClientKey::new(client_key.clone(), 0_u8);

	let fhe_string = str_client_key.encrypt(&clear_string).trim();
	let dec_string = str_client_key.decrypt(&fhe_string);
	println!("Start string: '{dec_string}'");


	let pattern = args.pattern.unwrap();
	let fhe_pattern = str_nopad_client_key.encrypt(&pattern);
	
	let fhe_op = fhe_string.clone() + fhe_pattern.clone();
	let dec_string = str_client_key.decrypt(&fhe_op);
	println!("Concat: {dec_string}");

	let fhe_op = fhe_string.eq(fhe_pattern.clone());
	let dec_bool = fhe_op.decrypt(&client_key);
	println!("Eq: {dec_bool}");

	let fhe_op = fhe_string.eq_ignore_case(fhe_pattern);
	let dec_bool = fhe_op.decrypt(&client_key);
	println!("Eq_i: {dec_bool}");

	let fhe_op = fhe_string.contains_clear(pattern.as_str());
	let dec_bool = fhe_op.decrypt(&client_key);
	println!("Contains: {dec_bool}");

	let fhe_op = fhe_string.starts_with_clear(pattern.as_str());
	let dec_bool = fhe_op.decrypt(&client_key);
	println!("Starts with: {dec_bool}");

	let fhe_op = fhe_string.ends_with_clear(pattern.as_str());
	let dec_bool = fhe_op.decrypt(&client_key);
	println!("Ends with: {dec_bool}");

	// let fhe_op = fhe_string + str_client_key.encrypt("_added");
	// let dec_string = str_client_key.decrypt(&fhe_op);
	// println!("Concat: '{dec_string}'");

	// let fhe_op = fhe_string.trim_start();
	// let dec_string = str_client_key.decrypt(&fhe_op);
	// println!("Trim start string: '{dec_string}'");

	// let fhe_op = fhe_string.trim();
	// let dec_string = str_client_key.decrypt(&fhe_op);
	// println!("Trim: '{dec_string}'");

	// let fhe_op = fhe_op.repeat_clear(2);
	// let dec_string = str_client_key.decrypt(&fhe_op);
	// println!("Repeat clear: '{dec_string}'");

	// let fhe_op = fhe_string.repeat(FheUint8::encrypt(2_u8, &client_key));
	// let dec_string = str_client_key.decrypt(&fhe_op);
	// println!("Repeat: '{dec_string}'");

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

fn gen_server_keys_for_threads(config: Config, num_threads: usize) -> ClientKey{
    let client_key = ClientKey::generate(config);
	if num_threads > 1 {
		rayon::ThreadPoolBuilder::new()
		   // .use_current_thread()
		   .num_threads(4) // TODO remove
		   .spawn_handler(|thread| {
			   let server_key = client_key.generate_server_key();
			   std::thread::spawn(move || {
				   set_server_key(server_key.clone());
				   thread.run()
			   });
			   Ok(())
		   }
	   ).build_global().unwrap();
	}
	set_server_key(client_key.generate_server_key());
	info!("Generated server keys for all threads");

	client_key
}