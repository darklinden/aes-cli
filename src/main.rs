use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use hkdf::Hkdf;
use sha2::Sha256;

#[derive(Parser)]
#[command(name = "aes-cli")]
#[command(about = "Encrypt or decrypt files using AES-256", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file using AES-256
    Enc {
        /// The input file to encrypt
        input_file: String,

        /// The output file to write the encrypted data
        output_file: String,

        /// Password to use for encryption (if not provided, AES_PWD environment variable will be used)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Decrypt a file encrypted with AES-256
    Dec {
        /// The encrypted input file
        input_file: String,

        /// The output file to write the decrypted data
        output_file: String,

        /// Password used for encryption (if not provided, AES_PWD environment variable will be used)
        #[arg(short, long)]
        password: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Enc {
            input_file,
            output_file,
            password,
        } => {
            let pwd = get_password(password)?;
            encrypt_file(&input_file, &output_file, &pwd).context("Failed to encrypt file")?;
            println!("File encrypted successfully: {}", output_file);
        }
        Commands::Dec {
            input_file,
            output_file,
            password,
        } => {
            let pwd = get_password(password)?;
            decrypt_file(&input_file, &output_file, &pwd).context("Failed to decrypt file")?;
            println!("File decrypted successfully: {}", output_file);
        }
    }

    Ok(())
}

// Helper function to get password from argument or environment variable
fn get_password(password_arg: Option<String>) -> Result<String> {
    match password_arg {
        Some(pwd) => Ok(pwd),
        None => env::var("AES_PWD")
            .context("Password not provided and AES_PWD environment variable not set"),
    }
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];

    // Use HKDF with SHA-256 for key derivation
    let hk = Hkdf::<Sha256>::new(Some(salt), password.as_bytes());
    hk.expand(&[], &mut key).map_err(|e| anyhow::anyhow!(e))?;

    Ok(key)
}

// Chunk size for processing large files (4MB)
const CHUNK_SIZE: usize = 4 * 1024 * 1024;
// Magic bytes to identify our file format (AESC)
const MAGIC_BYTES: [u8; 4] = [0x41, 0x45, 0x53, 0x43];
// Format version
const FORMAT_VERSION: u8 = 1;

fn encrypt_file(input_path: &str, output_path: &str, password: &str) -> Result<()> {
    // Open input file with buffered reader
    let input_file =
        File::open(input_path).context(format!("Failed to open input file: {}", input_path))?;
    let file_size = input_file.metadata()?.len();
    let mut reader = BufReader::new(input_file);

    // Generate salt and base nonce
    let mut salt = [0u8; 16];
    let mut base_nonce = [0u8; 12]; // 96 bits for GCM
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut base_nonce);

    // Derive key from password and salt
    let key_bytes = derive_key(password, &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Create output file with buffered writer
    let output_file = File::create(output_path)
        .context(format!("Failed to create output file: {}", output_path))?;
    let mut writer = BufWriter::new(output_file);

    // Write file header: magic bytes + format version + salt + base_nonce + file_size
    writer
        .write_all(&MAGIC_BYTES)
        .context("Failed to write magic bytes")?;
    writer
        .write_all(&[FORMAT_VERSION])
        .context("Failed to write format version")?;
    writer.write_all(&salt).context("Failed to write salt")?;
    writer
        .write_all(&base_nonce)
        .context("Failed to write base nonce")?;
    writer
        .write_all(&file_size.to_le_bytes())
        .context("Failed to write file size")?;

    // Process file in chunks
    let mut buffer = vec![0; CHUNK_SIZE];
    let mut chunk_index: u32 = 0;

    loop {
        // Read chunk from input file
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        // Create unique nonce for this chunk by XORing base_nonce with chunk_index
        let mut chunk_nonce = base_nonce;
        let chunk_bytes = chunk_index.to_le_bytes();
        for i in 0..4 {
            if i < chunk_nonce.len() {
                chunk_nonce[i] ^= chunk_bytes[i];
            }
        }
        let nonce = Nonce::from_slice(&chunk_nonce);

        // Encrypt the chunk
        let plaintext = &buffer[..bytes_read];
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!(e))?;

        // Write the encrypted chunk size and the encrypted data
        let chunk_size = ciphertext.len() as u32;
        writer
            .write_all(&chunk_size.to_le_bytes())
            .context("Failed to write chunk size")?;
        writer
            .write_all(&ciphertext)
            .context("Failed to write encrypted chunk")?;

        chunk_index += 1;
    }

    writer.flush().context("Failed to flush output buffer")?;

    Ok(())
}

fn decrypt_file(input_path: &str, output_path: &str, password: &str) -> Result<()> {
    // Open the encrypted file with buffered reader
    let input_file =
        File::open(input_path).context(format!("Failed to open encrypted file: {}", input_path))?;
    let mut reader = BufReader::new(input_file);

    // Read and verify magic bytes
    let mut magic = [0u8; 4];
    reader
        .read_exact(&mut magic)
        .context("Failed to read file header, file may not be in the correct format")?;

    if magic != MAGIC_BYTES {
        return Err(anyhow::anyhow!(
            "Invalid file format: this doesn't appear to be a file encrypted with this tool, or it's corrupted"
        ));
    }

    // Read format version
    let mut version = [0u8; 1];
    reader
        .read_exact(&mut version)
        .context("Failed to read format version")?;

    if version[0] != FORMAT_VERSION {
        return Err(anyhow::anyhow!(
            "Incompatible file format version: Expected version {}, found version {}",
            FORMAT_VERSION,
            version[0]
        ));
    }

    // Read header: salt, base nonce, and file size
    let mut salt = [0u8; 16];
    let mut base_nonce = [0u8; 12];
    let mut file_size_bytes = [0u8; 8]; // u64

    reader
        .read_exact(&mut salt)
        .context("Failed to read salt, file may be corrupted")?;
    reader
        .read_exact(&mut base_nonce)
        .context("Failed to read base nonce, file may be corrupted")?;
    reader
        .read_exact(&mut file_size_bytes)
        .context("Failed to read file size, file may be corrupted")?;
    let file_size = u64::from_le_bytes(file_size_bytes);

    // Derive key from password and salt
    let key_bytes = derive_key(password, &salt)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Create output file with buffered writer
    let output_file = File::create(output_path)
        .context(format!("Failed to create output file: {}", output_path))?;
    let mut writer = BufWriter::new(output_file);

    // Process file in chunks
    let mut chunk_index: u32 = 0;
    let mut bytes_written: u64 = 0;

    while bytes_written < file_size {
        // Read chunk size
        let mut chunk_size_bytes = [0u8; 4];
        if let Err(e) = reader.read_exact(&mut chunk_size_bytes) {
            if bytes_written == file_size {
                // We've reached the end of the file
                break;
            }
            return Err(e).context("Failed to read chunk size, file may be corrupted");
        }

        let chunk_size = u32::from_le_bytes(chunk_size_bytes) as usize;
        if chunk_size > 10 * CHUNK_SIZE {
            // Sanity check - chunk shouldn't be more than 10x our normal chunk size
            return Err(anyhow::anyhow!(
                "Invalid chunk size: {}, file may be corrupted",
                chunk_size
            ));
        }

        // Read encrypted chunk
        let mut encrypted_chunk = vec![0u8; chunk_size];
        reader
            .read_exact(&mut encrypted_chunk)
            .context("Failed to read encrypted chunk")?;

        // Create unique nonce for this chunk
        let mut chunk_nonce = base_nonce;
        let chunk_bytes = chunk_index.to_le_bytes();
        for i in 0..4 {
            if i < chunk_nonce.len() {
                chunk_nonce[i] ^= chunk_bytes[i];
            }
        }
        let nonce = Nonce::from_slice(&chunk_nonce);

        // Decrypt chunk
        let decrypted_chunk = cipher
            .decrypt(nonce, encrypted_chunk.as_ref())
            .map_err(|e| anyhow::anyhow!(e))?;

        // Write decrypted chunk to output
        let bytes_to_write =
            std::cmp::min(decrypted_chunk.len() as u64, file_size - bytes_written) as usize;
        writer
            .write_all(&decrypted_chunk[..bytes_to_write])
            .context("Failed to write decrypted data")?;

        bytes_written += bytes_to_write as u64;
        chunk_index += 1;
    }

    writer.flush().context("Failed to flush output buffer")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_encrypt_decrypt() -> Result<()> {
        let dir = tempdir()?;
        let input_path = dir.path().join("input.bytes");
        println!("Input path: {:?}", input_path);
        let encrypted_path = dir.path().join("encrypted.bytes.enc");
        let decrypted_path = dir.path().join("decrypted.bytes");

        let password = "testpassword";

        // Create a sample input file
        let mut input_file = File::create(&input_path)?;

        let mut large_content = vec![0u8; 10 * 1024 * 1024]; // 10MB of zero bytes
        OsRng.fill_bytes(&mut large_content);
        input_file.write_all(&large_content)?;

        // Encrypt the file
        encrypt_file(
            input_path.to_str().unwrap(),
            encrypted_path.to_str().unwrap(),
            password,
        )?;

        // Decrypt the file
        decrypt_file(
            encrypted_path.to_str().unwrap(),
            decrypted_path.to_str().unwrap(),
            password,
        )?;

        // Verify the decrypted file matches the original input file
        let original_content = fs::read(input_path)?;
        let decrypted_content = fs::read(decrypted_path)?;
        assert_eq!(original_content, decrypted_content);

        Ok(())
    }

    #[test]
    fn test_invalid_password() -> Result<()> {
        let dir = tempdir()?;
        let input_path = dir.path().join("input.txt");
        let encrypted_path = dir.path().join("encrypted.aes");
        let decrypted_path = dir.path().join("decrypted.txt");

        let password = "testpassword";
        let wrong_password = "wrongpassword";

        // Create a sample input file
        let mut input_file = File::create(&input_path)?;
        writeln!(input_file, "This is a test file.")?;

        // Encrypt the file
        encrypt_file(
            input_path.to_str().unwrap(),
            encrypted_path.to_str().unwrap(),
            password,
        )?;

        // Attempt to decrypt the file with the wrong password
        let result = decrypt_file(
            encrypted_path.to_str().unwrap(),
            decrypted_path.to_str().unwrap(),
            wrong_password,
        );

        // Verify that decryption fails
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_corrupted_file() -> Result<()> {
        let dir = tempdir()?;
        let input_path = dir.path().join("input.txt");
        let encrypted_path = dir.path().join("encrypted.aes");
        let decrypted_path = dir.path().join("decrypted.txt");

        let password = "testpassword";

        // Create a sample input file
        let mut input_file = File::create(&input_path)?;
        writeln!(input_file, "This is a test file.")?;

        // Encrypt the file
        encrypt_file(
            input_path.to_str().unwrap(),
            encrypted_path.to_str().unwrap(),
            password,
        )?;

        // Corrupt the encrypted file by modifying its content
        let mut encrypted_file = File::open(&encrypted_path)?;
        let mut content = Vec::new();
        encrypted_file.read_to_end(&mut content)?;
        content[10] ^= 0xFF; // Flip a bit to corrupt the file
        let mut corrupted_file = File::create(&encrypted_path)?;
        corrupted_file.write_all(&content)?;

        // Attempt to decrypt the corrupted file
        let result = decrypt_file(
            encrypted_path.to_str().unwrap(),
            decrypted_path.to_str().unwrap(),
            password,
        );

        // Verify that decryption fails
        assert!(result.is_err());

        Ok(())
    }
}
