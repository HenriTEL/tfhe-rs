// A CLI
//
// Input:
//     string to be encrypted
//     <optional> pattern for string functions which require it
//
// Output: Nicely formatted comparison with std::str results.
// the ouptuts will be nicely formatted for the user to see that the results match
// (if there are errors then the bounty would not be considered valid) with timing information for
// the FHE version.

use std::time::Instant;

use ciphertext::FheString;
use clap::Parser;
mod ciphertext;
mod client_key;
mod pattern_matcher;

use client_key::StringClientKey;
use env_logger::Env;
use log::info;
use tfhe::prelude::*;
use tfhe::{
    set_server_key, ClientKey, Config, ConfigBuilder, FheBool, FheInt16, FheUint16, FheUint8,
};

use crate::ciphertext::MaxedFheUint8;

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
    let args = Args::parse();
    assert!(args.clear_string.is_some(), "clear_string required");
    let clear_str = args.clear_string.unwrap();

    let config = ConfigBuilder::default().build();
    let client_key = gen_server_keys_for_threads(config, 64);

    println!(
        "{0: <20} | {1: <10} | {2: <10} | {3: <10} | {4: <10}",
        "Function", "Success", "Seconds", "Std Result", "Fhe Result"
    );
    let str_client_key = client_key::StringClientKey::new(client_key.clone(), 0);
    let fhe_str = str_client_key.encrypt(&clear_str);

    [
        "len",
        "trim_start",
        "trim_end",
        "trim",
        "is_empty",
        "to_uppercase",
        "to_lowercase",
    ]
    .into_iter()
    .for_each(|function| check_result_no_arg(&str_client_key, &fhe_str, &clear_str, function));
    check_repeat(&str_client_key, &fhe_str, &clear_str, "repeat");

    if args.pattern.is_none() {
        return;
    }
    let clear_pattern = args.pattern.unwrap();
    let mut common_pattern_fn = vec![
        "contains",
        "starts_with",
        "ends_with",
        "find",
        "rfind",
        "strip_prefix",
        "strip_suffix",
    ];
    common_pattern_fn.iter().for_each(|function| {
        check_result_clear_pattern(
            &str_client_key,
            &fhe_str,
            &clear_str,
            &clear_pattern,
            function,
        )
    });

    if clear_pattern.contains('\0') {
        panic!("Padding not supported for the pattern.");
    }
    common_pattern_fn.extend(["eq", "ne", "eq_ignore_case"]);
    let fhe_pattern = str_client_key.encrypt(&clear_pattern);
    println!();
    common_pattern_fn.into_iter().for_each(|function| {
        check_result_enc_pattern(
            &str_client_key,
            &fhe_str,
            &clear_str,
            &clear_pattern,
            &fhe_pattern,
            function,
        )
    });
}

fn check_result_no_arg(
    client_key: &StringClientKey,
    fhe_str: &FheString,
    clear_str: &str,
    function: &str,
) {
    let start = Instant::now();
    let op_result = match function {
        "len" => OpResult::U16(fhe_str.len()),
        "trim_start" => OpResult::String(fhe_str.trim_start()),
        "trim_end" => OpResult::String(fhe_str.trim_end()),
        "trim" => OpResult::String(fhe_str.trim()),
        "is_empty" => OpResult::Bool(fhe_str.is_empty()),
        "to_uppercase" => OpResult::String(fhe_str.to_uppercase()),
        "to_lowercase" => OpResult::String(fhe_str.to_lowercase()),
        _ => panic!("Unexpected function"),
    };
    let precision_factor = 1000.0;
    let duration = (start.elapsed().as_secs_f32() * precision_factor).round() / precision_factor;
    let std_result = match function {
        "len" => clear_str.len().to_string(),
        "trim_start" => clear_str.trim_start().to_string(),
        "trim_end" => clear_str.trim_end().to_string(),
        "trim" => clear_str.trim().to_string(),
        "is_empty" => clear_str.is_empty().to_string(),
        "to_uppercase" => clear_str.to_uppercase().to_string(),
        "to_lowercase" => clear_str.to_lowercase().to_string(),
        _ => panic!("Unexpected function"),
    };
    let clear_result = op_result.to_string(client_key);
    let results_match = (std_result == clear_result).to_string();
    println!(
        "{0: <20} | {1: <10} | {2: <10} | {3: <10} | {4: <10}",
        function, results_match, duration, std_result, clear_result
    );
}

fn check_result_clear_pattern(
    client_key: &StringClientKey,
    fhe_str: &FheString,
    clear_str: &str,
    clear_pattern: &str,
    function: &str,
) {
    let start = Instant::now();
    let op_result = match function {
        "contains" => OpResult::Bool(fhe_str.contains_clear(clear_pattern)),
        "starts_with" => OpResult::Bool(fhe_str.starts_with_clear(clear_pattern)),
        "ends_with" => OpResult::Bool(fhe_str.ends_with_clear(clear_pattern)),
        "find" => OpResult::I16(fhe_str.find_clear(clear_pattern)),
        "rfind" => OpResult::I16(fhe_str.rfind_clear(clear_pattern)),
        "strip_prefix" => OpResult::String(fhe_str.strip_prefix_clear(clear_pattern)),
        "strip_suffix" => OpResult::String(fhe_str.strip_suffix_clear(clear_pattern)),
        _ => panic!("Unexpected function"),
    };
    let precision_factor = 1000.0;
    let duration = (start.elapsed().as_secs_f32() * precision_factor).round() / precision_factor;
    let std_result = match function {
        "contains" => clear_str.contains(clear_pattern).to_string(),
        "starts_with" => clear_str.starts_with(clear_pattern).to_string(),
        "ends_with" => clear_str.ends_with(clear_pattern).to_string(),
        "find" => match clear_str.find(clear_pattern) {
            Some(r) => r as isize,
            None => -1,
        }
        .to_string(),
        "rfind" => match clear_str.rfind(clear_pattern) {
            Some(r) => r as isize,
            None => -1,
        }
        .to_string(),
        "strip_prefix" => match clear_str.strip_prefix(clear_pattern) {
            Some(s) => s,
            None => clear_str,
        }
        .to_string(),
        "strip_suffix" => match clear_str.strip_suffix(clear_pattern) {
            Some(s) => s,
            None => clear_str,
        }
        .to_string(),
        _ => panic!("Unexpected function"),
    };
    let clear_result = op_result.to_string(client_key);
    let results_match = (std_result == clear_result).to_string();
    println!(
        "{0: <20} | {1: <10} | {2: <10} | {3: <10} | {4: <10}",
        function.to_owned() + "_clear",
        results_match,
        duration,
        std_result,
        clear_result
    );
}

fn check_result_enc_pattern(
    client_key: &StringClientKey,
    fhe_str: &FheString,
    clear_str: &str,
    clear_pattern: &str,
    fhe_pattern: &FheString,
    function: &str,
) {
    let start = Instant::now();
    let op_result = match function {
        "contains" => OpResult::Bool(fhe_str.contains(fhe_pattern)),
        "starts_with" => OpResult::Bool(fhe_str.starts_with(fhe_pattern)),
        "ends_with" => OpResult::Bool(fhe_str.ends_with(fhe_pattern)),
        "eq" => OpResult::Bool(fhe_str.eq(fhe_pattern)),
        "ne" => OpResult::Bool(fhe_str.ne(fhe_pattern)),
        "eq_ignore_case" => OpResult::Bool(fhe_str.eq_ignore_case(fhe_pattern)),
        "find" => OpResult::I16(fhe_str.find(fhe_pattern)),
        "rfind" => OpResult::I16(fhe_str.rfind(fhe_pattern)),
        "strip_prefix" => OpResult::String(fhe_str.strip_prefix(fhe_pattern)),
        "strip_suffix" => OpResult::String(fhe_str.strip_suffix(fhe_pattern)),
        _ => panic!("Unexpected function"),
    };
    let precision_factor = 1000.0;
    let duration = (start.elapsed().as_secs_f32() * precision_factor).round() / precision_factor;
    let std_result = match function {
        "contains" => clear_str.contains(clear_pattern).to_string(),
        "starts_with" => clear_str.starts_with(clear_pattern).to_string(),
        "ends_with" => clear_str.ends_with(clear_pattern).to_string(),
        "eq" => (clear_str == clear_pattern).to_string(),
        "ne" => (clear_str != clear_pattern).to_string(),
        "eq_ignore_case" => clear_str.eq_ignore_ascii_case(clear_pattern).to_string(),
        "find" => match clear_str.find(clear_pattern) {
            Some(r) => r as isize,
            None => -1,
        }
        .to_string(),
        "rfind" => match clear_str.rfind(clear_pattern) {
            Some(r) => r as isize,
            None => -1,
        }
        .to_string(),
        "strip_prefix" => match clear_str.strip_prefix(clear_pattern) {
            Some(s) => s,
            None => clear_str,
        }
        .to_string(),
        "strip_suffix" => match clear_str.strip_suffix(clear_pattern) {
            Some(s) => s,
            None => clear_str,
        }
        .to_string(),
        _ => panic!("Unexpected function"),
    };
    let clear_result = op_result.to_string(client_key);
    let results_match = (std_result == clear_result).to_string();
    println!(
        "{0: <20} | {1: <10} | {2: <10} | {3: <10} | {4: <10}",
        function, results_match, duration, std_result, clear_result
    );
}
fn check_repeat(
    client_key: &StringClientKey,
    fhe_str: &FheString,
    clear_str: &str,
    function: &str,
) {
    let std_result = clear_str.repeat(2);
    let start = Instant::now();
    let op_result = OpResult::String(fhe_str.repeat_clear(2));

    let precision_factor = 1000.0;
    let duration = (start.elapsed().as_secs_f32() * precision_factor).round() / precision_factor;
    let clear_result = op_result.to_string(client_key);
    let results_match = (std_result == clear_result).to_string();
    println!(
        "{0: <20} | {1: <10} | {2: <10} | {3: <10} | {4: <10}",
        function, results_match, duration, std_result, clear_result
    );
    println!();

    let maxed_enc_u8 = MaxedFheUint8 {
        val: FheUint8::encrypt(2_u8, &client_key.key),
        max_val: 2,
    };
    let start = Instant::now();
    let op_result = OpResult::String(fhe_str.repeat(maxed_enc_u8));

    let precision_factor = 1000.0;
    let duration = (start.elapsed().as_secs_f32() * precision_factor).round() / precision_factor;
    let clear_result = op_result.to_string(client_key);
    let results_match = (std_result == clear_result).to_string();
    println!(
        "{0: <20} | {1: <10} | {2: <10} | {3: <10} | {4: <10}",
        function.to_owned() + "_clear",
        results_match,
        duration,
        std_result,
        clear_result
    );
}
enum OpResult {
    Bool(FheBool),
    String(FheString),
    I16(FheInt16),
    U16(FheUint16),
}

impl OpResult {
    fn to_string(&self, client_key: &StringClientKey) -> String {
        match self {
            OpResult::Bool(b) => b.decrypt(&client_key.key).to_string(),
            OpResult::String(s) => client_key.decrypt(s),
            OpResult::U16(u) => {
                let r: u16 = u.decrypt(&client_key.key);
                r.to_string()
            }
            OpResult::I16(i) => {
                let r: i16 = i.decrypt(&client_key.key);
                r.to_string()
            }
        }
    }
}

fn gen_server_keys_for_threads(config: Config, num_threads: usize) -> ClientKey {
    let client_key = ClientKey::generate(config);
    if num_threads > 1 {
        rayon::ThreadPoolBuilder::new()
            .use_current_thread()
            .num_threads(num_threads)
            .spawn_handler(|thread| {
                let server_key = client_key.generate_server_key();
                std::thread::spawn(move || {
                    set_server_key(server_key.clone());
                    thread.run()
                });
                Ok(())
            })
            .build_global()
            .unwrap();
    }
    set_server_key(client_key.generate_server_key());
    info!("Generated server keys for all {num_threads} threads");

    client_key
}
