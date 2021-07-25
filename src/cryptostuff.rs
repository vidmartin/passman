
use crypto::buffer::{self, ReadBuffer, WriteBuffer};
use crypto::digest::Digest;

pub fn hash_str(input: &str) -> String {
    let mut hasher = crypto::sha2::Sha256::new();
    hasher.input_str(input);
    let mut pwd_hash_bytes_attempt_store: [u8; 256] = [0; 256];    
    hasher.result(&mut pwd_hash_bytes_attempt_store);
    let pwd_hash_bytes_attempt = &pwd_hash_bytes_attempt_store[0..hasher.output_bytes()];
    return base64::encode(pwd_hash_bytes_attempt);
}

pub fn encrypt_str(input: &str, key_str: &str) -> String {
    let key = get_key_from_password(key_str);

    let mut encryptor = crypto::aes::cbc_encryptor(
        crypto::aes::KeySize::KeySize256,
        &key, &key[0..16], crypto::blockmodes::PkcsPadding);
        
    let encrypted_data = transform_data(
        input.as_bytes(),
        |read_buf, write_buf| {
            encryptor.encrypt(read_buf, write_buf, true)
        }
    ).unwrap();

    return base64::encode(encrypted_data);
}

pub fn decrypt_str(input_str: &str, key_str: &str) -> String {
    let key = get_key_from_password(key_str);

    let mut decryptor = crypto::aes::cbc_decryptor(
        crypto::aes::KeySize::KeySize256,
        &key, &key[0..16], crypto::blockmodes::PkcsPadding);

    let input_bytes = base64::decode(input_str).unwrap();
        
    let decrypted_data = transform_data(
        input_bytes.as_ref(),
        |read_buf, write_buf| {
            decryptor.decrypt(read_buf, write_buf, true)
        }
    ).unwrap();

    return String::from_utf8(decrypted_data).unwrap();
}

fn transform_data<F>(input: &[u8], mut iteration: F) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError>
    where F: FnMut(&mut crypto::buffer::RefReadBuffer, &mut crypto::buffer::RefWriteBuffer) -> Result<crypto::buffer::BufferResult, crypto::symmetriccipher::SymmetricCipherError>
{
    let mut output_vec = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(input);
    let mut write_buffer_array: [u8; 4096] = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut write_buffer_array);

    loop {
        let result = iteration(&mut read_buffer, &mut write_buffer)?;

        output_vec.extend(write_buffer.take_read_buffer().take_remaining().iter());

        match result {
            buffer::BufferResult::BufferUnderflow => break,
            buffer::BufferResult::BufferOverflow => { }
        }
    }

    return Ok(output_vec);
}

fn get_key_from_password(password: &str) -> Vec<u8> {
    let mut key: [u8; 32] = [0; 32];
    for (index, byte) in password.as_bytes().iter().enumerate() {
        key[index] = *byte;

        if index + 1 == key.len() {
            break;
        }
    }

    return key.to_vec();
}