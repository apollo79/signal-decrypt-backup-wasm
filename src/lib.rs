// helper functions for protobufs
pub(crate) mod bytes_serde {
    use prost::bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Option<Bytes>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => serializer.serialize_bytes(b),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Bytes>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<Vec<u8>>::deserialize(deserializer).map(|opt| opt.map(|vec| Bytes::from(vec)))
    }
}

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr32BE;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use prost::Message;
use sha2::{Digest, Sha256, Sha512};
use std::io::{self, Read};
use wasm_bindgen::prelude::*;

extern crate console_error_panic_hook;

pub mod signal {
    include!(concat!(env!("OUT_DIR"), "/signal.rs"));
}

type HmacSha256 = Hmac<Sha256>;

#[wasm_bindgen]
pub struct DecryptionResult {
    database_bytes: Vec<u8>,
}

#[wasm_bindgen]
impl DecryptionResult {
    #[wasm_bindgen(getter)]
    pub fn database_bytes(&self) -> Vec<u8> {
        self.database_bytes.clone()
    }
}

// Add position field to ByteReader
struct ByteReader {
    data: Vec<u8>,
    position: usize,
}

// cusstom reader implementation, like `io::BufReader`
// when data is read, it will on a subsequent read_exact call start at the point where it stopped before
impl ByteReader {
    fn new(data: Vec<u8>) -> Self {
        ByteReader { data, position: 0 }
    }

    fn remaining_data(&self) -> &[u8] {
        &self.data[self.position..]
    }

    fn remaining_length(&self) -> usize {
        self.remaining_data().len()
    }

    fn get_position(&self) -> usize {
        self.position
    }

    fn set_position(&mut self, new_position: usize) {
        self.position = new_position;
    }

    fn increment_position(&mut self, interval: usize) {
        self.position += interval;
    }

    // reads data into a passed buffer
    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let available = self.remaining_data();

        if available.len() < buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected end of file",
            ));
        }
        buf.copy_from_slice(&available[..buf.len()]);
        self.position += buf.len();
        Ok(())
    }
}

impl Read for ByteReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let available = self.data.len() - self.position;
        let amount = buf.len().min(available);

        if amount == 0 {
            return Ok(0);
        }

        buf[..amount].copy_from_slice(&self.data[self.position..self.position + amount]);
        self.position += amount;
        Ok(amount)
    }
}

struct HeaderData {
    initialisation_vector: Vec<u8>,
    salt: Vec<u8>,
    version: Option<u32>,
}

struct Keys {
    cipher_key: Vec<u8>,
    hmac_key: Vec<u8>,
}

fn io_err_to_js(e: io::Error) -> JsValue {
    JsValue::from_str(&format!("IO Error: {}", e))
}

fn sql_parameter_to_string(
    parameter: &signal::sql_statement::SqlParameter,
) -> Result<String, JsValue> {
    if let Some(s) = &parameter.string_paramter {
        Ok(format!("'{}'", s.replace("'", "''")))
    } else if let Some(i) = parameter.integer_parameter {
        let signed_i = if i & (1 << 63) != 0 {
            i | (-1_i64 << 63) as u64
        } else {
            i
        };
        Ok(signed_i.to_string())
    } else if let Some(d) = parameter.double_parameter {
        Ok(d.to_string())
    } else if let Some(b) = &parameter.blob_parameter {
        Ok(format!("X'{}'", hex::encode(b)))
    } else if parameter.nullparameter.is_some() {
        Ok("NULL".to_string())
    } else {
        Ok("NULL".to_string())
    }
}

// concatenates an sql string with placeholders with parameters
fn process_parameter_placeholders(sql: &str, params: &[String]) -> Result<String, JsValue> {
    let mut result = sql.to_string();
    let mut param_index = 0;

    while param_index < params.len() {
        let rest = &result[param_index..];

        // Find the next placeholders
        // signal backups only use the standard type and not indexed or other ones
        let next_placeholder = rest.find('?').map(|i| (i, 1)); // ? style

        match next_placeholder {
            Some((pos, len)) => {
                // Replace the placeholder with the parameter value
                if param_index < params.len() {
                    let before = &result[..param_index + pos];
                    let after = &result[param_index + pos + len..];
                    result = format!("{}{}{}", before, params[param_index], after);
                    param_index += 1;
                } else {
                    return Err(JsValue::from_str(
                        "Not enough parameters provided for SQL statement",
                    ));
                }
            }
            None => {
                // No more placeholders found
                break;
            }
        }
    }

    // Check if we have unused parameters
    if param_index < params.len() {
        web_sys::console::warn_1(
            &format!(
                "Warning: {} parameters were provided but not all were used in SQL: {}",
                params.len(),
                sql
            )
            .into(),
        );
    }

    Ok(result)
}

fn derive_keys(passphrase: &str, salt: &[u8]) -> Result<Keys, JsValue> {
    let passphrase_bytes = passphrase.replace(" ", "").as_bytes().to_vec();

    let mut hash = passphrase_bytes.clone();
    let mut sha512 = Sha512::new();

    Digest::update(&mut sha512, salt);

    for _ in 0..250000 {
        Digest::update(&mut sha512, &hash);
        Digest::update(&mut sha512, &passphrase_bytes);
        hash = sha512.finalize_reset().to_vec();
    }

    let hkdf = Hkdf::<Sha256>::new(Some(b""), &hash[..32]);
    let mut keys = vec![0u8; 64];
    hkdf.expand(b"Backup Export", &mut keys)
        .map_err(|_| JsValue::from_str("HKDF expand failed"))?;

    Ok(Keys {
        cipher_key: keys[..32].to_vec(),
        hmac_key: keys[32..].to_vec(),
    })
}

fn increment_initialisation_vector(initialisation_vector: &[u8]) -> Vec<u8> {
    let mut counter = u32::from_be_bytes(initialisation_vector[..4].try_into().unwrap());
    counter = (counter + 1) & 0xFFFFFFFF;
    let mut new_iv = counter.to_be_bytes().to_vec();
    new_iv.extend_from_slice(&initialisation_vector[4..]);
    new_iv
}

// read initial cryptographic information (initialisation_vector, salt) and backup version
fn read_backup_header(reader: &mut ByteReader) -> Result<HeaderData, JsValue> {
    let mut length_bytes = [0u8; 4];
    reader
        .read_exact(&mut length_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to read header length: {}", e)))?;

    let length = u32::from_be_bytes(length_bytes);

    let mut backup_frame_bytes = vec![0u8; length as usize];
    reader
        .read_exact(&mut backup_frame_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to read backup frame: {}", e)))?;

    let backup_frame = signal::BackupFrame::decode(&backup_frame_bytes[..])
        .map_err(|e| JsValue::from_str(&format!("Failed to decode backup frame: {}", e)))?;

    let header = backup_frame
        .header
        .ok_or_else(|| JsValue::from_str("Missing header"))?;

    Ok(HeaderData {
        initialisation_vector: header.iv.unwrap().to_vec(),
        salt: header.salt.unwrap().to_vec(),
        version: header.version,
    })
}

// read the frame length, which is encrypted in the first 4 bytes of a frame
fn get_frame_length(
    reader: &mut ByteReader,
    hmac: &mut HmacSha256,
    ctr: &mut Ctr32BE<Aes256>,
    header_version: Option<u32>,
) -> Result<Option<u32>, JsValue> {
    if reader.remaining_length() < 4 {
        return Ok(None); // Not enough data to read the frame length
    }

    // in the old version, the length of the frames was not encrypted
    let length = match header_version {
        None => {
            let mut length_bytes = [0u8; 4];
            reader.read_exact(&mut length_bytes).map_err(io_err_to_js)?;
            let len = u32::from_be_bytes(length_bytes);
            len
        }
        Some(1) => {
            let mut encrypted_length = [0u8; 4];
            reader
                .read_exact(&mut encrypted_length)
                .map_err(io_err_to_js)?;

            Mac::update(hmac, &encrypted_length);

            let mut decrypted_length = encrypted_length;
            ctr.apply_keystream(&mut decrypted_length);

            u32::from_be_bytes(decrypted_length)
        }
        Some(v) => return Err(JsValue::from_str(&format!("Unsupported version: {}", v))),
    };

    Ok(Some(length))
}

// decrypt the frame content
fn decrypt_frame(
    reader: &mut ByteReader,
    mut hmac: HmacSha256,
    ctr: &mut Ctr32BE<Aes256>,
    ciphertext_buf: &mut Vec<u8>,
    plaintext_buf: &mut Vec<u8>,
    frame_length: u32,
) -> Result<Option<signal::BackupFrame>, JsValue> {
    if reader.remaining_length() < frame_length as usize {
        return Ok(None); // Not enough data to read the frame
    }

    ciphertext_buf.clear();
    ciphertext_buf.resize((frame_length - 10) as usize, 0);
    reader.read_exact(ciphertext_buf).map_err(io_err_to_js)?;

    let mut their_mac = [0u8; 10];
    reader.read_exact(&mut their_mac).map_err(io_err_to_js)?;

    Mac::update(&mut hmac, ciphertext_buf);
    let our_mac = hmac.finalize().into_bytes();

    if their_mac != our_mac[..10] {
        return Err(JsValue::from_str(&format!(
            "MAC verification failed. Their MAC: {:02x?}, Our MAC: {:02x?}",
            their_mac,
            &our_mac[..10]
        )));
    }

    plaintext_buf.clear();
    plaintext_buf.extend_from_slice(ciphertext_buf);
    ctr.apply_keystream(plaintext_buf);

    // Attempt to decode the frame
    let backup_frame = signal::BackupFrame::decode(&plaintext_buf[..])
        .map_err(|e| JsValue::from_str(&format!("Failed to decode frame: {}", e)))?;

    Ok(Some(backup_frame))
}

#[wasm_bindgen]
pub struct BackupDecryptor {
    reader: ByteReader,
    keys: Option<Keys>,
    header_data: Option<HeaderData>,
    initialisation_vector: Option<Vec<u8>>,
    database_bytes: Vec<u8>,
    ciphertext_buf: Vec<u8>,
    plaintext_buf: Vec<u8>,
    total_file_size: usize,
    total_bytes_processed: usize,
    processed_percentage: usize,
    progress_callback: Option<js_sys::Function>,
    is_initialized: bool,
    // this is stored if the frame has been decrypted but it is an attachment for which we don't have enough data available
    // so we don't need to decrypt the whole frame again
    current_backup_frame: Option<signal::BackupFrame>,
}

#[wasm_bindgen]
impl BackupDecryptor {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        console_error_panic_hook::set_once();

        Self {
            reader: ByteReader::new(Vec::new()),
            keys: None,
            header_data: None,
            initialisation_vector: None,
            database_bytes: Vec::new(),
            ciphertext_buf: Vec::new(),
            plaintext_buf: Vec::new(),
            total_file_size: 0,
            total_bytes_processed: 0,
            processed_percentage: 0,
            progress_callback: None,
            is_initialized: false,
            current_backup_frame: None,
        }
    }

    // provide more data of the backup while keeping potentially existing data
    #[wasm_bindgen]
    pub fn feed_data(&mut self, chunk: &[u8]) {
        let current_size = self.reader.remaining_data().len();
        let mut new_data = Vec::with_capacity(current_size + chunk.len());
        new_data.extend_from_slice(self.reader.remaining_data());
        new_data.extend_from_slice(chunk);

        // self.total_bytes_received += chunk.len();
        self.reader = ByteReader::new(new_data);
    }

    #[wasm_bindgen]
    pub fn set_progress_callback(
        &mut self,
        total_file_size: usize,
        progress_callback: js_sys::Function,
    ) {
        self.total_file_size = total_file_size;
        self.progress_callback = Some(progress_callback);
    }

    pub fn call_progress_callback(&self) -> usize {
        let prev_percentage = self.processed_percentage;

        if let Some(ref progress_callback) = self.progress_callback {
            let percentage =
                (self.total_bytes_processed as f32 / self.total_file_size as f32) * 100.0;

            let rounded = percentage.round() as usize;

            if rounded != prev_percentage {
                progress_callback
                    .call1(&JsValue::NULL, &JsValue::from(rounded))
                    .unwrap();

                return rounded;
            }
        }

        return prev_percentage;
    }

    // process available data
    // returns Ok if the decryption of the current frame was successful
    // Ok(false) if there is enough data left
    // Ok(true) if there is not enough data to decrypt the next frame -> new data should be provided using `feed_data`
    // Ok(true) if this was the last frame
    #[wasm_bindgen]
    pub fn process_chunk(&mut self, passphrase: &str) -> Result<bool, JsValue> {
        if !self.is_initialized {
            self.header_data = Some(read_backup_header(&mut self.reader)?);
            let header_data = self.header_data.as_ref().unwrap();
            self.keys = Some(derive_keys(passphrase, &header_data.salt)?);
            self.initialisation_vector = Some(header_data.initialisation_vector.clone());
            self.is_initialized = true;

            return Ok(false);
        }

        let keys = self.keys.as_ref().unwrap();
        let header_data = self.header_data.as_ref().unwrap();
        let iv = self.initialisation_vector.as_ref().unwrap();

        // this case happens when we had to load a new chunk because there wasn't enough data to fully decrypt the attachment
        if self.current_backup_frame.is_some() {
            let backup_frame_cloned = self.current_backup_frame.clone().unwrap();

            let length = if let Some(attachment) = backup_frame_cloned.attachment {
                attachment.length.unwrap_or(0)
            } else if let Some(sticker) = backup_frame_cloned.sticker {
                sticker.length.unwrap_or(0)
            } else if let Some(avatar) = backup_frame_cloned.avatar {
                avatar.length.unwrap_or(0)
            } else {
                return Err(JsValue::from_str("Invalid field type found"));
            };

            if self.reader.remaining_length() < length as usize {
                return Ok(true);
            } else {
                self.total_bytes_processed += (length + 10) as usize;
                let new_percentage = self.call_progress_callback();
                self.processed_percentage = new_percentage;

                // attachments are encoded as length, which would have to be read using decode_frame_payload
                // +10 because in decrypt_frame_payload we would read `their_mac` from reader which is 10 bytes long
                self.reader.increment_position((length + 10) as usize);

                // after attachments, we have to increment again
                self.initialisation_vector = Some(increment_initialisation_vector(iv));

                self.current_backup_frame = None;

                return Ok(false);
            }
        } else {
            // we need to do this here so that during get_frame_length and decrypt_frame we use the same hmac and ctr
            let mut hmac = <HmacSha256 as Mac>::new_from_slice(&keys.hmac_key)
                .map_err(|_| JsValue::from_str("Invalid HMAC key"))?;

            let mut ctr = <Ctr32BE<Aes256> as KeyIvInit>::new_from_slices(&keys.cipher_key, iv)
                .map_err(|_| JsValue::from_str("Invalid CTR parameters"))?;

            let initial_reader_position = self.reader.get_position();

            let frame_length = match get_frame_length(
                &mut self.reader,
                &mut hmac,
                &mut ctr,
                header_data.version,
            ) {
                Ok(None) => {
                    // need to reset the position here because getting the length and decrypting the frame rely on
                    // the same hmac / ctr and if we don't read the position first they won't be correct
                    self.reader.set_position(initial_reader_position);
                    return Ok(true);
                }
                Ok(Some(length)) => length,
                Err(e) => return Err(e),
            };

            // if we got to an attachment, but there we demand more data, it will be faulty, because we try to decrypt the frame although we would need
            // to decrypt the attachment
            match decrypt_frame(
                &mut self.reader,
                hmac,
                &mut ctr,
                &mut self.ciphertext_buf,
                &mut self.plaintext_buf,
                frame_length,
            ) {
                Ok(None) => {
                    return Ok(true);
                }
                Ok(Some(backup_frame)) => {
                    // +4 because the length which was read is 4 bytes long
                    self.total_bytes_processed += (frame_length + 4) as usize;
                    let new_percentage = self.call_progress_callback();
                    self.processed_percentage = new_percentage;

                    // can not assign right here because of borrowing issues
                    let mut new_iv = increment_initialisation_vector(iv);

                    if backup_frame.end.unwrap_or(false) {
                        self.initialisation_vector = Some(new_iv);
                        return Ok(true);
                    }

                    // Handle all frame types
                    if let Some(version) = backup_frame.version {
                        if let Some(ver_num) = version.version {
                            let pragma_sql = format!("PRAGMA user_version = {}", ver_num);
                            self.database_bytes.extend_from_slice(pragma_sql.as_bytes());
                            self.database_bytes.push(b';');
                        }
                    } else if let Some(statement) = backup_frame.statement {
                        if let Some(sql) = statement.statement {
                            if !sql.to_lowercase().starts_with("create table sqlite_")
                                && !sql.contains("sms_fts_")
                                && !sql.contains("mms_fts_")
                            {
                                let processed_sql = if !statement.parameters.is_empty() {
                                    let params: Vec<String> = statement
                                        .parameters
                                        .iter()
                                        .map(|param| sql_parameter_to_string(param))
                                        .collect::<Result<_, _>>()?;

                                    process_parameter_placeholders(&sql, &params)?
                                } else {
                                    sql
                                };

                                // Add to concatenated string
                                self.database_bytes
                                    .extend_from_slice(processed_sql.as_bytes());
                                self.database_bytes.push(b';');
                            }
                        }
                    } else if backup_frame.preference.is_some() || backup_frame.key_value.is_some()
                    {
                    } else {
                        // we just skip these types here
                        let backup_frame_cloned = backup_frame.clone();

                        let length = if let Some(attachment) = backup_frame_cloned.attachment {
                            attachment.length.unwrap_or(0)
                        } else if let Some(sticker) = backup_frame_cloned.sticker {
                            sticker.length.unwrap_or(0)
                        } else if let Some(avatar) = backup_frame_cloned.avatar {
                            avatar.length.unwrap_or(0)
                        } else {
                            return Err(JsValue::from_str("Invalid field type found"));
                        };

                        if self.reader.remaining_length() < length as usize {
                            // important: we need to apply the first new_iv here, else it won't be correct when resuming payload decryption
                            // as we return, we don't get to the final assignment below
                            self.initialisation_vector = Some(new_iv);

                            self.current_backup_frame = Some(backup_frame.clone());

                            return Ok(true);
                        } else {
                            self.total_bytes_processed += (length + 10) as usize;
                            let new_percentage = self.call_progress_callback();
                            self.processed_percentage = new_percentage;

                            // attachments are encoded as length, which would have to be read using decode_frame_payload
                            // +10 because in decrypt_frame_payload we would read `their_mac` from reader which is 10 bytes long
                            self.reader.increment_position((length + 10) as usize);

                            new_iv = increment_initialisation_vector(&new_iv);
                        }
                    }

                    // here we can finally assign
                    self.initialisation_vector = Some(new_iv);
                    Ok(false)
                }
                Err(e) => {
                    if e.as_string()
                        .map_or(false, |s| s.contains("unexpected end of file"))
                    {
                        Ok(false)
                    } else {
                        Err(e)
                    }
                }
            }
        }
    }

    #[wasm_bindgen]
    pub fn finish(self) -> Result<DecryptionResult, JsValue> {
        Ok(DecryptionResult {
            database_bytes: self.database_bytes,
        })
    }
}
