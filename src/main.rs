extern crate aes;
extern crate block_modes;
extern crate pbkdf2;
extern crate sha2;
extern crate hex;
extern crate hmac;

use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use pbkdf2::{pbkdf2};
use sha2::Sha256;
use hmac::Hmac;
use std::fs::File;
use std::io::{Read, Write};
use std::env;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

const KEY_SIZE: usize = 32;
const IV_SIZE: usize = 16;
const SALT: &[u8] = &[];

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: ./rust -encrypt <input_filename> <passphrase>  ");
        eprintln!("Usage: ./rust -decrypt <input_filename> <key_filename> ");

        std::process::exit(1);
    }

    match args[1].as_str() {
        "-encrypt" => encrypt(&args[2], &args[3]),
        "-decrypt" => {
            if args.len() != 4 {
                eprintln!("For decryption, provide the key.txt file.");
                std::process::exit(1);
            }
            decrypt(&args[2], &args[3])
        },
        _ => {
           eprintln!("Invalid option. Use -encrypt or -decrypt or -exec.");
           std::process::exit(1);
        }
    }
}

fn encrypt(input_filename: &str passphrase: &str) -> std::io::Result<()> {

    let mut key = vec![0u8; KEY_SIZE];
    pbkdf2::<Hmac<Sha256>>(passphrase.as_bytes(), SALT, 100_000, &mut key);

    let mut file = File::open(input_filename)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let iv = vec![0u8; IV_SIZE];

    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    let encrypted_data = cipher.encrypt_vec(&data);

    let encrypted_filename = format!("{}_encrypted", input_filename);
    let mut encrypted_file = File::create(&encrypted_filename)?;
    encrypted_file.write_all(&encrypted_data)?;

    let mut key_file = File::create("key.txt")?;
    key_file.write_all(&key)?;

    println!("Encrypted file: {}, key written to key.txt", encrypted_filename);
    Ok(())
}

fn decrypt(input_filename: &str, key_filename: &str) -> std::io::Result<()> {
    let mut key_file = File::open(key_filename)?;
    let mut key = Vec::new();
    key_file.read_to_end(&mut key)?;

    let iv = vec![0u8; IV_SIZE];

    let mut encrypted_file = File::open(input_filename)?;
    let mut encrypted_data = Vec::new();
    encrypted_file.read_to_end(&mut encrypted_data)?;

    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    let decrypted_data = cipher.decrypt_vec(&encrypted_data).unwrap();

    let decrypted_filename = "decrypted.bin".to_string();
    let mut decrypted_file = File::create(&decrypted_filename)?;
    decrypted_file.write_all(&decrypted_data)?;

    println!("Decryption complete.{}", decrypted_filename);

    Ok(())
}
