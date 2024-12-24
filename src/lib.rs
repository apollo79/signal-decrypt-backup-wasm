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
use std::collections::HashMap;
use std::io::{self, Read};
use wasm_bindgen::prelude::*;

extern crate console_error_panic_hook;

type HmacSha256 = Hmac<Sha256>;

pub mod signal {
    include!(concat!(env!("OUT_DIR"), "/signal.rs"));
}

#[derive(Debug)]
enum AttachmentType {
    Attachment,
    Sticker,
    Avatar,
}

#[wasm_bindgen]
pub struct DecryptionResult {
    database_bytes: Vec<u8>,
    preferences: String,
    key_values: String,
}

#[wasm_bindgen]
impl DecryptionResult {
    #[wasm_bindgen(getter)]
    pub fn database_bytes(&self) -> Vec<u8> {
        self.database_bytes.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn preferences(&self) -> String {
        self.preferences.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn key_values(&self) -> String {
        self.key_values.clone()
    }
}

// Add position field to ByteReader
struct ByteReader {
    data: Vec<u8>,
    position: usize,
}

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

    fn set_position(&mut self, position: usize) {
        self.position = position;
    }

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

fn io_err_to_js(e: io::Error) -> JsValue {
    JsValue::from_str(&format!("IO Error: {}", e))
}

fn decrypt_frame(
    reader: &mut ByteReader,
    hmac_key: &[u8],
    cipher_key: &[u8],
    initialisation_vector: &[u8],
    header_version: Option<u32>,
    ciphertext_buf: &mut Vec<u8>,
    plaintext_buf: &mut Vec<u8>,
    should_update_hmac: bool,
) -> Result<Option<signal::BackupFrame>, JsValue> {
    if reader.remaining_length() < 4 {
        web_sys::console::log_1(&"too less data to decrypt frame length".into());

        return Ok(None); // Not enough data to read the frame length
    }

    let initial_position = reader.get_position();

    let mut hmac = <HmacSha256 as Mac>::new_from_slice(hmac_key)
        .map_err(|_| JsValue::from_str("Invalid HMAC key"))?;

    let mut ctr =
        <Ctr32BE<Aes256> as KeyIvInit>::new_from_slices(cipher_key, initialisation_vector)
            .map_err(|_| JsValue::from_str("Invalid CTR parameters"))?;

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

            // web_sys::console::log_1(
            //     &format!("encrypted length bytes: {:02x?}", encrypted_length).into(),
            // );

            if should_update_hmac == true {
                // web_sys::console::log_1(&"updating hmac".into());

                Mac::update(&mut hmac, &encrypted_length);
            }

            let mut decrypted_length = encrypted_length;
            ctr.apply_keystream(&mut decrypted_length);

            // web_sys::console::log_1(
            //     &format!("decrypted length bytes: {:02x?}", decrypted_length).into(),
            // );

            let len = u32::from_be_bytes(decrypted_length);
            // web_sys::console::log_1(&format!("length: {}", len).into());
            len
        }
        Some(v) => return Err(JsValue::from_str(&format!("Unsupported version: {}", v))),
    };

    if reader.remaining_length() < length as usize {
        // web_sys::console::log_1(&"remaining data is too less".into());

        // reset the buffer for the next iteration
        reader.set_position(initial_position);
        return Ok(None); // Not =enough data to read the frame
    }

    ciphertext_buf.clear();
    ciphertext_buf.resize((length - 10) as usize, 0);
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

    // web_sys::console::log_1(&format!("position: {}", reader.get_position()).into());
    // if reader.remaining_length() >= 10 {
    //     web_sys::console::log_1(
    //         &format!("remaining data: {:02x?}", &reader.remaining_data()[..10]).into(),
    //     );
    // }

    Ok(Some(backup_frame))
}

// this decrypts attachments, stickers and avatars in chunks
fn decrypt_frame_payload(
    reader: &mut ByteReader,
    length: usize,
    hmac_key: &[u8],
    cipher_key: &[u8],
    initialisation_vector: &[u8],
    chunk_size: usize,
) -> Result<Option<Vec<u8>>, JsValue> {
    if reader.remaining_length() < length {
        // web_sys::console::log_1(&"too little data to decrypt attachment".into());
        // web_sys::console::log_1(
        //     &format!(
        //         "payload: too little remaining data: {:02x?}",
        //         &reader.remaining_data()[..10]
        //     )
        //     .into(),
        // );
        return Ok(None);
    } else {
        // web_sys::console::log_1(
        //     &format!(
        //         "payload: enough remaining data: {:02x?}",
        //         &reader.remaining_data()[..10]
        //     )
        //     .into(),
        // );
    }

    let mut hmac = <HmacSha256 as Mac>::new_from_slice(hmac_key)
        .map_err(|_| JsValue::from_str("Invalid HMAC key"))?;
    Mac::update(&mut hmac, initialisation_vector);

    let mut ctr =
        <Ctr32BE<Aes256> as KeyIvInit>::new_from_slices(cipher_key, initialisation_vector)
            .map_err(|_| JsValue::from_str("Invalid CTR parameters"))?;

    let mut decrypted_data = Vec::new();
    let mut remaining_length = length;

    while remaining_length > 0 {
        let this_chunk_length = remaining_length.min(chunk_size);
        remaining_length -= this_chunk_length;

        let mut ciphertext = vec![0u8; this_chunk_length];
        reader
            .read_exact(&mut ciphertext)
            .map_err(|e| JsValue::from_str(&format!("Failed to read chunk: {}", e)))?;
        Mac::update(&mut hmac, &ciphertext);

        let mut decrypted_chunk = ciphertext;
        ctr.apply_keystream(&mut decrypted_chunk);
        decrypted_data.extend(decrypted_chunk);
    }

    let mut their_mac = [0u8; 10];

    reader
        .read_exact(&mut their_mac)
        .map_err(|e| JsValue::from_str(&format!("Failed to read MAC: {}", e)))?;

    let our_mac = hmac.finalize().into_bytes();

    if &their_mac != &our_mac[..10] {
        return Err(JsValue::from_str(&format!(
            "payload: MAC verification failed. Their MAC: {:02x?}, Our MAC: {:02x?}",
            their_mac,
            &our_mac[..10]
        )));
    }

    Ok(Some(decrypted_data))
}

#[wasm_bindgen]
pub struct BackupDecryptor {
    reader: ByteReader,
    keys: Option<Keys>,
    header_data: Option<HeaderData>,
    initialisation_vector: Option<Vec<u8>>,
    database_bytes: Vec<u8>,
    preferences: HashMap<String, HashMap<String, HashMap<String, serde_json::Value>>>,
    key_values: HashMap<String, HashMap<String, serde_json::Value>>,
    attachments: HashMap<String, Vec<u8>>,
    stickers: HashMap<String, Vec<u8>>,
    avatars: HashMap<String, Vec<u8>>,
    ciphertext_buf: Vec<u8>,
    plaintext_buf: Vec<u8>,
    total_bytes_received: usize,
    is_initialized: bool,
    should_update_hmac_next_run: bool,
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
            preferences: HashMap::new(),
            key_values: HashMap::new(),
            attachments: HashMap::new(),
            stickers: HashMap::new(),
            avatars: HashMap::new(),
            ciphertext_buf: Vec::new(),
            plaintext_buf: Vec::new(),
            total_bytes_received: 0,
            is_initialized: false,
            should_update_hmac_next_run: true,
            current_backup_frame: None,
        }
    }

    #[wasm_bindgen]
    pub fn feed_data(&mut self, chunk: &[u8]) {
        // web_sys::console::log_1(
        //     &format!("feeding: position: {}", self.reader.get_position()).into(),
        // );
        // if self.reader.remaining_length() >= 10 {
        // web_sys::console::log_1(
        //     &format!(
        //         "feeding: remaining data: {:02x?}",
        //         &self.reader.remaining_data()[..10]
        //     )
        //     .into(),
        // );
        // }

        let current_size = self.reader.remaining_data().len();
        let mut new_data = Vec::with_capacity(current_size + chunk.len());
        new_data.extend_from_slice(self.reader.remaining_data());
        new_data.extend_from_slice(chunk);

        self.total_bytes_received += chunk.len();
        self.reader = ByteReader::new(new_data);
    }

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
            // web_sys::console::log_1(
            //     &"going direct to payload decryption after loading new chunk".into(),
            // );

            let backup_frame_cloned = self.current_backup_frame.clone().unwrap();

            let (filename, length, attachment_type) =
                if let Some(attachment) = backup_frame_cloned.attachment {
                    (
                        format!("{}.bin", attachment.row_id.unwrap_or(0)),
                        attachment.length.unwrap_or(0),
                        AttachmentType::Attachment,
                    )
                } else if let Some(sticker) = backup_frame_cloned.sticker {
                    (
                        format!("{}.bin", sticker.row_id.unwrap_or(0)),
                        sticker.length.unwrap_or(0),
                        AttachmentType::Sticker,
                    )
                } else if let Some(avatar) = backup_frame_cloned.avatar {
                    (
                        format!("{}.bin", avatar.recipient_id.unwrap_or_default()),
                        avatar.length.unwrap_or(0),
                        AttachmentType::Avatar,
                    )
                } else {
                    return Err(JsValue::from_str("Invalid field type found"));
                };

            match decrypt_frame_payload(
                &mut self.reader,
                length as usize,
                &keys.hmac_key,
                &keys.cipher_key,
                // have to use new_iv!
                iv.as_ref(),
                8 * 1024,
            ) {
                Ok(None) => {
                    // no need to assign newly here, can stay the same as we need to load even more data
                    return Ok(true);
                }
                Ok(Some(payload)) => {
                    self.current_backup_frame = None;

                    // match attachment_type {
                    //     AttachmentType::Attachment => {
                    //         self.attachments.insert(filename, payload);
                    //     }
                    //     AttachmentType::Sticker => {
                    //         self.stickers.insert(filename, payload);
                    //     }
                    //     AttachmentType::Avatar => {
                    //         self.avatars.insert(filename, payload);
                    //     }
                    // }
                    // after attachments, we have to increment again
                    self.initialisation_vector = Some(increment_initialisation_vector(iv));
                }
                Err(e) => return Err(e),
            }

            return Ok(false);
        }

        // if we got to an attachment, but there we demand more data, it will be faulty, because we try to decrypt the frame although we would need
        // to decrypt the attachment
        match decrypt_frame(
            &mut self.reader,
            &keys.hmac_key,
            &keys.cipher_key,
            iv,
            header_data.version,
            &mut self.ciphertext_buf,
            &mut self.plaintext_buf,
            self.should_update_hmac_next_run,
        ) {
            Ok(None) => {
                self.should_update_hmac_next_run = false;
                return Ok(true);
            }
            Ok(Some(backup_frame)) => {
                self.should_update_hmac_next_run = true;

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
                            self.database_bytes.extend_from_slice(sql.as_bytes());
                            self.database_bytes.push(b';');
                        }
                    }
                } else if let Some(preference) = backup_frame.preference {
                    let value_dict = self
                        .preferences
                        .entry(preference.file.unwrap_or_default())
                        .or_default()
                        .entry(preference.key.unwrap_or_default())
                        .or_default();

                    if let Some(value) = preference.value {
                        value_dict.insert("value".to_string(), serde_json::Value::String(value));
                    }
                    if let Some(boolean_value) = preference.boolean_value {
                        value_dict.insert(
                            "booleanValue".to_string(),
                            serde_json::Value::Bool(boolean_value),
                        );
                    }
                    if preference.is_string_set_value.unwrap_or(false) {
                        value_dict.insert(
                            "stringSetValue".to_string(),
                            serde_json::Value::Array(
                                preference
                                    .string_set_value
                                    .into_iter()
                                    .map(serde_json::Value::String)
                                    .collect(),
                            ),
                        );
                    }
                } else if let Some(key_value) = backup_frame.key_value {
                    let value_dict = self
                        .key_values
                        .entry(key_value.key.unwrap_or_default())
                        .or_default();

                    if let Some(boolean_value) = key_value.boolean_value {
                        value_dict.insert(
                            "booleanValue".to_string(),
                            serde_json::Value::Bool(boolean_value),
                        );
                    }
                    if let Some(float_value) = key_value.float_value {
                        value_dict.insert(
                            "floatValue".to_string(),
                            serde_json::Value::Number(
                                serde_json::Number::from_f64(float_value.into()).unwrap(),
                            ),
                        );
                    }
                    if let Some(integer_value) = key_value.integer_value {
                        value_dict.insert(
                            "integerValue".to_string(),
                            serde_json::Value::Number(integer_value.into()),
                        );
                    }
                    if let Some(long_value) = key_value.long_value {
                        value_dict.insert(
                            "longValue".to_string(),
                            serde_json::Value::Number(long_value.into()),
                        );
                    }
                    if let Some(string_value) = key_value.string_value {
                        value_dict.insert(
                            "stringValue".to_string(),
                            serde_json::Value::String(string_value),
                        );
                    }
                    if let Some(blob_value) = key_value.blob_value {
                        value_dict.insert(
                            "blobValueBase64".to_string(),
                            serde_json::Value::String(base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                &blob_value,
                            )),
                        );
                    }
                } else {
                    let backup_frame_cloned = backup_frame.clone();

                    let (filename, length, attachment_type) =
                        if let Some(attachment) = backup_frame_cloned.attachment {
                            (
                                format!("{}.bin", attachment.row_id.unwrap_or(0)),
                                attachment.length.unwrap_or(0),
                                AttachmentType::Attachment,
                            )
                        } else if let Some(sticker) = backup_frame_cloned.sticker {
                            (
                                format!("{}.bin", sticker.row_id.unwrap_or(0)),
                                sticker.length.unwrap_or(0),
                                AttachmentType::Sticker,
                            )
                        } else if let Some(avatar) = backup_frame_cloned.avatar {
                            (
                                format!("{}.bin", avatar.recipient_id.unwrap_or_default()),
                                avatar.length.unwrap_or(0),
                                AttachmentType::Avatar,
                            )
                        } else {
                            return Err(JsValue::from_str("Invalid field type found"));
                        };

                    match decrypt_frame_payload(
                        &mut self.reader,
                        length as usize,
                        &keys.hmac_key,
                        &keys.cipher_key,
                        // have to use new_iv!
                        new_iv.as_ref(),
                        8 * 1024,
                    ) {
                        Ok(None) => {
                            // important: we need to apply the first new_iv here, else it won't be correct when resuming payload decryption
                            // as we return, we don't get to the final assignment below
                            self.initialisation_vector = Some(new_iv);

                            self.current_backup_frame = Some(backup_frame.clone());

                            return Ok(true);
                        }
                        Ok(Some(payload)) => {
                            // match attachment_type {
                            //     AttachmentType::Attachment => {
                            //         self.attachments.insert(filename, payload);
                            //     }
                            //     AttachmentType::Sticker => {
                            //         self.stickers.insert(filename, payload);
                            //     }
                            //     AttachmentType::Avatar => {
                            //         self.avatars.insert(filename, payload);
                            //     }
                            // }
                            // after attachments, we have to increment again
                            new_iv = increment_initialisation_vector(&new_iv);
                        }
                        Err(e) => return Err(e),
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

    #[wasm_bindgen]
    pub fn finish(self) -> Result<DecryptionResult, JsValue> {
        Ok(DecryptionResult {
            database_bytes: self.database_bytes,
            preferences: serde_json::to_string(&self.preferences).map_err(|e| {
                JsValue::from_str(&format!("Failed to serialize preferences: {}", e))
            })?,
            key_values: serde_json::to_string(&self.key_values).map_err(|e| {
                JsValue::from_str(&format!("Failed to serialize key_values: {}", e))
            })?,
        })
    }
}
