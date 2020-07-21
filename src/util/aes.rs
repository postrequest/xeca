extern crate aes_soft as aes;
extern crate block_modes;
extern crate rand;

use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use aes::Aes128;
use rand::{Rng, seq};

// Convenient alias
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

// Encrypt data with AES CBC to decrypt with PowerShell
// https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesmanaged
pub fn encrypt(plaintext: &str)  -> ([u8; 16], Vec<u8>) {
    let plaintext_bytes = plaintext.as_bytes();
    let mut rng = rand::thread_rng();
    let key: [u8; 16] = rng.gen();
    let iv:  [u8; 16] = rng.gen();
    let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();
    let ciphertext = cipher.encrypt_vec(plaintext_bytes);
    // prepend IV to ciphertext for PowerShell payload to use
    let mut iv_ciphertext = Vec::new();
    iv_ciphertext.extend_from_slice(&iv);
    iv_ciphertext.extend_from_slice(&ciphertext[..]);
    (key, iv_ciphertext)
}

pub fn funnies() {
    let mut rng = rand::thread_rng();
    let fun = include_bytes!("../assets/fortunes.txt");
    let fun_string = String::from_utf8_lossy(fun);
    let lines: Vec<&str> = fun_string.split("\n").collect();
    let newline_count = fun.iter().filter(|&&c| c == b'\n').count();
    let sample = seq::sample_iter(&mut rng, 1..newline_count, 1).unwrap();
    println!("\n{}", lines.get(sample[0]).unwrap());
}
