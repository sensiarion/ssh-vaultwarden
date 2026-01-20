use crate::config::Config;
use crate::{Error, Result};
use crate::vault::{SshEntry, VaultApi};
use regex::Regex;
use log::debug;
use std::collections::{HashSet, VecDeque};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use base64::{Engine as _, engine::general_purpose};
use aes::Aes256;
use cbc::Decryptor;
use cipher::{KeyIvInit, block_padding::Pkcs7, BlockDecryptMut};
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, Oaep};
use rsa::pkcs8::DecodePrivateKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(rename = "expires_in")]
    _expires_in: u64,
    token_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CipherResponse {
    id: String,
    #[serde(rename = "type")]
    cipher_type: u8,
    name: String,
    notes: Option<String>,
    login: Option<LoginData>,
    collection_ids: Option<Vec<String>>,
    organization_id: Option<String>,
    #[serde(flatten)]
    _other: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CollectionResponse {
    id: String,
    name: String,
    organization_id: Option<String>,
    parent_id: Option<String>,
    #[serde(flatten)]
    _other: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncCache {
    ciphers: Vec<CipherResponse>,
    collections: Option<Vec<CollectionResponse>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoginData {
    username: Option<String>,
    password: Option<String>,
    uris: Option<Vec<UriData>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UriData {
    uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreloginResponse {
    kdf: u8,
    kdf_iterations: u32,
    #[serde(default)]
    kdf_memory: Option<u32>,
    #[serde(default)]
    kdf_parallelism: Option<u32>,
}

#[derive(Debug, Clone)]
struct SymmetricKey {
    enc_key: Vec<u8>,
    mac_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrganizationResponse {
    id: String,
    name: Option<String>,
    key: Option<String>,  // RSA-encrypted organization key
    #[serde(flatten)]
    _other: HashMap<String, serde_json::Value>,
}

pub struct RealVaultApi {
    config: Config,
    client: reqwest::blocking::Client,
    access_token: Option<String>,
    email: Option<String>,
    password: Option<String>,
    master_key: Option<[u8; 32]>,
    master_password_hash: Option<[u8; 32]>,
    user_key: Option<SymmetricKey>,
    private_key: Option<RsaPrivateKey>,
    org_keys: HashMap<String, SymmetricKey>,
    collections_cache: Option<Vec<CollectionResponse>>,
}

impl RealVaultApi {
    const CACHE_FILE: &'static str = ".ssh-vaultvarden-sync.json";

    fn cache_path() -> PathBuf {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(Self::CACHE_FILE)
    }

    fn cache_exists() -> bool {
        Self::cache_path().is_file()
    }

    fn load_cache() -> Result<Option<SyncCache>> {
        let path = Self::cache_path();
        if !path.is_file() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(&path)
            .map_err(|e| Error::Vault(format!("Failed to read cache file: {}", e)))?;
        let cache: SyncCache = serde_json::from_str(&content)
            .map_err(|e| Error::Vault(format!("Failed to parse cache file: {}", e)))?;
        Ok(Some(cache))
    }

    fn save_cache(cache: &SyncCache) -> Result<()> {
        let path = Self::cache_path();
        let content = serde_json::to_string_pretty(cache)
            .map_err(|e| Error::Vault(format!("Failed to serialize cache: {}", e)))?;
        std::fs::write(&path, content)
            .map_err(|e| Error::Vault(format!("Failed to write cache file: {}", e)))?;
        Ok(())
    }
    pub fn new(config: Config) -> Self {
        Self {
            config,
            client: reqwest::blocking::Client::new(),
            access_token: None,
            email: None,
            password: None,
            master_key: None,
            master_password_hash: None,
            user_key: None,
            private_key: None,
            org_keys: HashMap::new(),
            collections_cache: None,
        }
    }

    fn prelogin(&self, email: &str) -> Result<PreloginResponse> {
        let url = format!("{}/identity/accounts/prelogin", self.config.vault_url.trim_end_matches('/'));
        
        let mut params = HashMap::new();
        let normalized_email = email.trim().to_lowercase();
        params.insert("email", normalized_email.as_str());

        let response = self
            .client
            .post(&url)
            .json(&params)
            .send()
            .map_err(|e| Error::Vault(format!("Failed to connect to vault for prelogin: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().unwrap_or_else(|_| "Unknown error".to_string());
            return Err(Error::Vault(format!(
                "Prelogin failed with status {}: {}",
                status, text
            )));
        }

        let text = response.text()
            .map_err(|e| Error::Vault(format!("Failed to read prelogin response: {}", e)))?;
        
        let prelogin: PreloginResponse = serde_json::from_str(&text)
            .map_err(|e| Error::Vault(format!(
                "Failed to parse prelogin response: {}. Response body: {}",
                e, text
            )))?;

        Ok(prelogin)
    }

    fn pbkdf2_hash(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
        let mut hash = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut hash);
        hash
    }

    fn derive_master_key(email: &str, password: &str, kdf: u8, kdf_iterations: u32) -> Result<[u8; 32]> {
        match kdf {
            0 => {
                // CRITICAL: Bitwarden requires lowercase email as salt
                let salt = email.trim().to_lowercase();
                Ok(Self::pbkdf2_hash(password.as_bytes(), salt.as_bytes(), kdf_iterations))
            }
            _ => Err(Error::Vault(format!(
                "Argon2id KDF (type {}) not yet implemented. Please use PBKDF2 (kdf=0)",
                kdf
            ))),
        }
    }

    fn derive_master_password_hash(master_key: &[u8; 32], password: &str) -> [u8; 32] {
        // PBKDF2(master_key, password, 1)
        Self::pbkdf2_hash(master_key, password.as_bytes(), 1)
    }

    fn stretch_master_key(master_key: &[u8; 32]) -> Result<SymmetricKey> {
        // Bitwarden uses HKDF-Expand ONLY (no extract step)
        // The master key is used directly as the PRK (Pseudo-Random Key)
        // - info = "enc" for encryption key
        // - info = "mac" for MAC key
        let hkdf = Hkdf::<Sha256>::from_prk(master_key)
            .map_err(|_| Error::Vault("Failed to create HKDF from master key".to_string()))?;
        
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        
        // Expand with info "enc" to get encryption key
        hkdf.expand(b"enc", &mut enc_key)
            .map_err(|_| Error::Vault("Failed to derive enc key via HKDF".to_string()))?;
        
        // Expand with info "mac" to get MAC key
        hkdf.expand(b"mac", &mut mac_key)
            .map_err(|_| Error::Vault("Failed to derive mac key via HKDF".to_string()))?;

        debug!(
            "Stretched key - enc first 8 bytes: {:02x?}, mac first 8 bytes: {:02x?}",
            &enc_key[..8], &mac_key[..8]
        );

        Ok(SymmetricKey {
            enc_key: enc_key.to_vec(),
            mac_key: mac_key.to_vec(),
        })
    }

    fn decode_b64(input: &str) -> Result<Vec<u8>> {
        // Try standard base64 first (most common in Bitwarden)
        if let Ok(bytes) = general_purpose::STANDARD.decode(input.trim()) {
            return Ok(bytes);
        }
        // Try without padding
        if let Ok(bytes) = general_purpose::STANDARD_NO_PAD.decode(input.trim()) {
            return Ok(bytes);
        }
        // Try URL-safe variants
        if let Ok(bytes) = general_purpose::URL_SAFE.decode(input.trim()) {
            return Ok(bytes);
        }
        if let Ok(bytes) = general_purpose::URL_SAFE_NO_PAD.decode(input.trim()) {
            return Ok(bytes);
        }
        Err(Error::Vault(format!(
            "Failed to decode base64 data: {}",
            if input.len() > 50 {
                format!("{}...", &input[..50])
            } else {
                input.to_string()
            }
        )))
    }

    fn decrypt_enc_string(enc_string: &str, key: &SymmetricKey) -> Result<Vec<u8>> {
        // Validate key lengths
        if key.enc_key.len() != 32 {
            return Err(Error::Vault(format!(
                "Invalid encryption key length: expected 32 bytes, got {}",
                key.enc_key.len()
            )));
        }
        if key.mac_key.len() != 32 {
            return Err(Error::Vault(format!(
                "Invalid MAC key length: expected 32 bytes, got {}",
                key.mac_key.len()
            )));
        }

        let mut parts = enc_string.splitn(2, '.');
        let enc_type = parts
            .next()
            .ok_or_else(|| Error::Vault("Invalid enc string (missing type)".to_string()))?;
        let data = parts
            .next()
            .ok_or_else(|| Error::Vault("Invalid enc string (missing data)".to_string()))?;

        let enc_type: u8 = enc_type
            .parse()
            .map_err(|_| Error::Vault("Invalid enc string type".to_string()))?;

        let segments: Vec<&str> = data.split('|').collect();
        if enc_type == 2 && segments.len() != 3 {
            return Err(Error::Vault(format!(
                "Invalid enc string segments for type 2: expected 3, got {}",
                segments.len()
            )));
        }
        if enc_type == 1 && segments.len() != 2 {
            return Err(Error::Vault(format!(
                "Invalid enc string segments for type 1: expected 2, got {}",
                segments.len()
            )));
        }

        let iv = Self::decode_b64(segments[0])
            .map_err(|e| Error::Vault(format!("Invalid IV base64: {}", e)))?;
        
        // Validate IV length - AES-CBC requires exactly 16 bytes
        if iv.len() != 16 {
            return Err(Error::Vault(format!(
                "Invalid IV length: expected 16 bytes, got {}",
                iv.len()
            )));
        }

        let ciphertext = Self::decode_b64(segments[1])
            .map_err(|e| Error::Vault(format!("Invalid ciphertext base64: {}", e)))?;

        if ciphertext.is_empty() {
            return Err(Error::Vault("Ciphertext is empty".to_string()));
        }

        // For type 2, verify MAC before decryption
        if enc_type == 2 {
            let mac = Self::decode_b64(segments[2])
                .map_err(|e| Error::Vault(format!("Invalid MAC base64: {}", e)))?;

            // MAC should be 32 bytes (SHA256 HMAC output)
            if mac.len() != 32 {
                return Err(Error::Vault(format!(
                    "Invalid MAC length: expected 32 bytes, got {}",
                    mac.len()
                )));
            }

            // Verify MAC: HMAC-SHA256(key.mac_key, iv || ciphertext)
            let mut hmac = Hmac::<Sha256>::new_from_slice(&key.mac_key)
                .map_err(|_| Error::Vault("Invalid MAC key for HMAC".to_string()))?;
            hmac.update(&iv);
            hmac.update(&ciphertext);
            
            // Debug: compute MAC and compare
            let computed_mac = hmac.clone().finalize().into_bytes();
            debug!(
                "MAC comparison - expected first 8: {:02x?}, computed first 8: {:02x?}",
                &mac[..8], &computed_mac[..8]
            );
            hmac.verify_slice(&mac)
                .map_err(|_| Error::Vault("MAC validation failed - data may be corrupted or key is incorrect".to_string()))?;
        } else if enc_type != 1 {
            return Err(Error::Vault(format!(
                "Unsupported enc string type {}",
                enc_type
            )));
        }

        // Decrypt using AES-256-CBC
        let mut buffer = ciphertext.clone();
        let decryptor = Decryptor::<Aes256>::new_from_slices(&key.enc_key, &iv)
            .map_err(|e| Error::Vault(format!("Failed to create decryptor: {:?}", e)))?;
        let decrypted = decryptor
            .decrypt_padded_mut::<Pkcs7>(&mut buffer)
            .map_err(|e| Error::Vault(format!("AES decryption failed: {:?}", e)))?;

        Ok(decrypted.to_vec())
    }

    fn decode_key_bytes(decrypted: &[u8]) -> Result<Vec<u8>> {
        if decrypted.len() == 64 {
            return Ok(decrypted.to_vec());
        }

        if let Ok(text) = std::str::from_utf8(decrypted) {
            if text.contains('|') {
                let parts: Vec<&str> = text.split('|').collect();
                if parts.len() == 2 {
                    let enc = Self::decode_b64(parts[0])
                        .map_err(|_| Error::Vault("Invalid enc key base64".to_string()))?;
                    let mac = Self::decode_b64(parts[1])
                        .map_err(|_| Error::Vault("Invalid mac key base64".to_string()))?;
                    if enc.len() == 32 && mac.len() == 32 {
                        let mut combined = Vec::with_capacity(64);
                        combined.extend_from_slice(&enc);
                        combined.extend_from_slice(&mac);
                        return Ok(combined);
                    }
                }
            }

            if let Ok(decoded) = Self::decode_b64(text) {
                if decoded.len() == 64 {
                    return Ok(decoded);
                }
            }
        }

        Err(Error::Vault("Invalid decrypted key length".to_string()))
    }

    fn try_decode_raw_key(key_enc: &str) -> Option<Vec<u8>> {
        if let Ok(decoded) = Self::decode_b64(key_enc) {
            if decoded.len() == 64 {
                return Some(decoded);
            }
        }
        None
    }

    /// Decrypt the user's RSA private key using the user symmetric key
    fn decrypt_private_key(encrypted_key: &str, user_key: &SymmetricKey) -> Result<RsaPrivateKey> {
        let decrypted_der = Self::decrypt_enc_string(encrypted_key, user_key)?;
        
        // The decrypted data is the private key in DER format
        RsaPrivateKey::from_pkcs8_der(&decrypted_der)
            .map_err(|e| Error::Vault(format!("Failed to parse RSA private key: {}", e)))
    }

    /// Decrypt data using RSA-OAEP with SHA-1 (Bitwarden's default)
    fn decrypt_rsa(encrypted_data: &[u8], private_key: &RsaPrivateKey) -> Result<Vec<u8>> {
        // Try RSA-OAEP with SHA-1 first (Bitwarden's legacy default)
        let padding = Oaep::new::<sha1::Sha1>();
        if let Ok(decrypted) = private_key.decrypt(padding, encrypted_data) {
            return Ok(decrypted);
        }
        
        // Try RSA-OAEP with SHA-256
        let padding = Oaep::new::<Sha256>();
        if let Ok(decrypted) = private_key.decrypt(padding, encrypted_data) {
            return Ok(decrypted);
        }
        
        // Try PKCS1v15 as last resort
        if let Ok(decrypted) = private_key.decrypt(Pkcs1v15Encrypt, encrypted_data) {
            return Ok(decrypted);
        }
        
        Err(Error::Vault("Failed to decrypt RSA data with any padding scheme".to_string()))
    }

    /// Decrypt an organization key (RSA-encrypted with user's public key)
    fn decrypt_org_key(&self, encrypted_org_key: &str) -> Result<SymmetricKey> {
        let private_key = self.private_key.as_ref()
            .ok_or_else(|| Error::Vault("Private key not available for org key decryption".to_string()))?;
        
        // Parse the encrypted string format: "type.data" or just base64 data
        let encrypted_data = if encrypted_org_key.contains('.') {
            // Format: "type.base64data"
            let mut parts = encrypted_org_key.splitn(2, '.');
            let enc_type = parts.next()
                .ok_or_else(|| Error::Vault("Invalid org key format".to_string()))?;
            let data = parts.next()
                .ok_or_else(|| Error::Vault("Invalid org key format".to_string()))?;
            
            debug!("Org key enc type: {}", enc_type);
            Self::decode_b64(data)?
        } else {
            Self::decode_b64(encrypted_org_key)?
        };
        
        let decrypted = Self::decrypt_rsa(&encrypted_data, private_key)?;
        
        // The decrypted org key should be 64 bytes (32 enc + 32 mac)
        if decrypted.len() == 64 {
            Ok(SymmetricKey {
                enc_key: decrypted[..32].to_vec(),
                mac_key: decrypted[32..].to_vec(),
            })
        } else if decrypted.len() == 32 {
            // If it's 32 bytes, we need to stretch it using HKDF
            let mut key_32: [u8; 32] = [0u8; 32];
            key_32.copy_from_slice(&decrypted);
            Self::stretch_master_key(&key_32)
        } else {
            Err(Error::Vault(format!(
                "Invalid org key length: expected 32 or 64 bytes, got {}",
                decrypted.len()
            )))
        }
    }

    fn enc_string_meta(enc_string: &str) -> Option<(u8, usize, usize, usize)> {
        let mut parts = enc_string.splitn(2, '.');
        let enc_type = parts.next()?.parse::<u8>().ok()?;
        let data = parts.next()?;
        let segments: Vec<&str> = data.split('|').collect();
        if enc_type == 2 && segments.len() == 3 {
            let iv_len = Self::decode_b64(segments[0]).ok()?.len();
            let ct_len = Self::decode_b64(segments[1]).ok()?.len();
            let mac_len = Self::decode_b64(segments[2]).ok()?.len();
            return Some((enc_type, iv_len, ct_len, mac_len));
        }
        if enc_type == 1 && segments.len() == 2 {
            let iv_len = Self::decode_b64(segments[0]).ok()?.len();
            let ct_len = Self::decode_b64(segments[1]).ok()?.len();
            return Some((enc_type, iv_len, ct_len, 0));
        }
        None
    }


    fn decrypt_string(&self, value: &str) -> Result<String> {
        // Handle empty strings
        if value.is_empty() {
            return Ok(String::new());
        }
        
        // If the value doesn't contain a dot, it's likely plain text (not encrypted)
        // Encrypted strings have format: "type.iv|ciphertext|mac"
        if !value.contains('.') {
            return Ok(value.to_string());
        }
        
        // Check if it looks like an encrypted string (starts with digit followed by dot)
        if !value.chars().next().map_or(false, |c| c.is_ascii_digit()) {
            // Not an encrypted string, return as-is
            return Ok(value.to_string());
        }
        
        let key = self
            .user_key
            .as_ref()
            .ok_or_else(|| Error::Vault("Missing user key for decryption".to_string()))?;
        let decrypted = Self::decrypt_enc_string(value, key)?;
        let text = String::from_utf8(decrypted)
            .map_err(|_| Error::Vault("Decrypted text is not valid UTF-8".to_string()))?;
        Ok(text)
    }

    fn decrypt_string_with_key(&self, value: &str, key: &SymmetricKey) -> Result<String> {
        // Handle empty strings
        if value.is_empty() {
            return Ok(String::new());
        }
        
        // If the value doesn't contain a dot, it's likely plain text (not encrypted)
        if !value.contains('.') {
            return Ok(value.to_string());
        }
        
        // Check if it looks like an encrypted string (starts with digit followed by dot)
        if !value.chars().next().map_or(false, |c| c.is_ascii_digit()) {
            return Ok(value.to_string());
        }
        
        let decrypted = Self::decrypt_enc_string(value, key)?;
        let text = String::from_utf8(decrypted)
            .map_err(|_| Error::Vault("Decrypted text is not valid UTF-8".to_string()))?;
        Ok(text)
    }

    fn hash_password_v1(email: &str, password: &str, kdf: u8, kdf_iterations: u32) -> Result<String> {
        // Single PBKDF2 hash (email as salt)
        match kdf {
            0 => {
                let salt = email.trim().to_lowercase();
                let hash = Self::pbkdf2_hash(password.as_bytes(), salt.as_bytes(), kdf_iterations);
                Ok(general_purpose::STANDARD.encode(hash))
            }
            _ => Err(Error::Vault(format!(
                "Argon2id KDF (type {}) not yet implemented. Please use PBKDF2 (kdf=0)",
                kdf
            ))),
        }
    }

    fn hash_password_v2(email: &str, password: &str, kdf: u8, kdf_iterations: u32) -> Result<String> {
        // Double PBKDF2 hash used by some Bitwarden clients:
        // 1) master_key = PBKDF2(password, email, iterations)
        // 2) password_hash = PBKDF2(master_key, password, 1)
        match kdf {
            0 => {
                let salt = email.trim().to_lowercase();
                let master_key = Self::pbkdf2_hash(password.as_bytes(), salt.as_bytes(), kdf_iterations);
                let password_hash = Self::pbkdf2_hash(&master_key, password.as_bytes(), 1);
                Ok(general_purpose::STANDARD.encode(password_hash))
            }
            _ => Err(Error::Vault(format!(
                "Argon2id KDF (type {}) not yet implemented. Please use PBKDF2 (kdf=0)",
                kdf
            ))),
        }
    }

    fn request_token(
        &self,
        email: &str,
        password_hash: &str,
        device_identifier: &str,
        device_name: &str,
    ) -> Result<TokenResponse> {
        let url = format!("{}/identity/connect/token", self.config.vault_url.trim_end_matches('/'));
        let normalized_email = email.trim().to_lowercase();
        
        let mut params = HashMap::new();
        params.insert("grant_type", "password");
        params.insert("username", normalized_email.as_str());
        params.insert("password", password_hash);
        params.insert("scope", "api offline_access");
        params.insert("client_id", "web");
        params.insert("device_identifier", device_identifier);
        params.insert("device_name", device_name);
        params.insert("device_type", "15"); // 15 = SDK (recommended for CLI/custom tools)

        let response = self
            .client
            .post(&url)
            .form(&params)
            .send()
            .map_err(|e| Error::Vault(format!("Failed to connect to vault: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().unwrap_or_else(|_| "Unknown error".to_string());
            return Err(Error::Vault(format!(
                "Login failed with status {}: {}",
                status, text
            )));
        }

        let token: TokenResponse = response
            .json()
            .map_err(|e| Error::Vault(format!("Failed to parse token response: {}", e)))?;

        Ok(token)
    }

    fn login(&mut self) -> Result<()> {
        let email = self.email.as_ref().ok_or_else(|| {
            Error::Vault("Email not provided. Call authenticate() first.".to_string())
        })?;
        let password = self.password.as_ref().ok_or_else(|| {
            Error::Vault("Password not provided. Call authenticate() first.".to_string())
        })?;

        // Step 1: Get KDF parameters from prelogin
        let prelogin = self.prelogin(email)?;
        debug!(
            "KDF parameters: type={}, iterations={}",
            prelogin.kdf, prelogin.kdf_iterations
        );
        let master_key = Self::derive_master_key(email, password, prelogin.kdf, prelogin.kdf_iterations)?;
        debug!(
            "Master key first 8 bytes: {:02x?}",
            &master_key[..8]
        );
        let master_password_hash = Self::derive_master_password_hash(&master_key, password);
        self.master_key = Some(master_key);
        self.master_password_hash = Some(master_password_hash);
        
        // Generate device identifier and name for this client
        let device_identifier = Uuid::new_v4().to_string();
        let device_name = format!("ssh-vaultvarden-{}", device_identifier);

        // Step 2: Try the standard PBKDF2 hash
        let password_hash_v1 =
            Self::hash_password_v1(email, password, prelogin.kdf, prelogin.kdf_iterations)?;
        let token = match self.request_token(email, &password_hash_v1, &device_identifier, &device_name) {
            Ok(token) => token,
            Err(err) => {
                let err_text = err.to_string();
                if err_text.contains("Username or password is incorrect") {
                    // Step 3: Fallback to the double-PBKDF2 hash used by some clients
                    let password_hash_v2 =
                        Self::hash_password_v2(email, password, prelogin.kdf, prelogin.kdf_iterations)?;
                    self.request_token(email, &password_hash_v2, &device_identifier, &device_name)?
                } else {
                    return Err(err);
                }
            }
        };

        self.access_token = Some(token.access_token);
        Ok(())
    }

    fn get_ciphers(&mut self) -> Result<Vec<CipherResponse>> {
        if let Some(cache) = Self::load_cache()? {
            debug!("Loaded {} ciphers from cache", cache.ciphers.len());
            self.collections_cache = cache.collections;
            return Ok(cache.ciphers);
        }

        let token = self
            .access_token
            .as_ref()
            .ok_or_else(|| Error::Vault("Not authenticated. Call authenticate() first.".to_string()))?;

        let url = format!("{}/api/sync", self.config.vault_url.trim_end_matches('/'));

        let response = self
            .client
            .get(&url)
            .bearer_auth(token)
            .send()
            .map_err(|e| Error::Vault(format!("Failed to fetch sync data: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().unwrap_or_else(|_| "Unknown error".to_string());
            return Err(Error::Vault(format!(
                "Failed to fetch sync data with status {}: {}",
                status, text
            )));
        }

        let text = response
            .text()
            .map_err(|e| Error::Vault(format!("Failed to read sync response: {}", e)))?;

        let value: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| Error::Vault(format!("Failed to parse sync data: {}. Response body: {}", e, text)))?;

        let profile = value
            .get("profile")
            .ok_or_else(|| Error::Vault("Missing profile in sync response".to_string()))?;
        let key_enc = profile
            .get("key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Vault("Missing profile key in sync response".to_string()))?;

        if let Some((enc_type, iv_len, ct_len, mac_len)) = Self::enc_string_meta(key_enc) {
            debug!(
                "Profile key enc type {}, iv {}, ct {}, mac {}",
                enc_type, iv_len, ct_len, mac_len
            );
        }

        // Try to decrypt the profile key using the master key
        // The profile key is typically encrypted, but some instances might store it as raw base64
        let user_key = if let Some(raw_key) = Self::try_decode_raw_key(key_enc) {
            debug!("Using raw profile key (64 bytes) - this is unusual, key should be encrypted");
            SymmetricKey {
                enc_key: raw_key[..32].to_vec(),
                mac_key: raw_key[32..].to_vec(),
            }
        } else {
            // Normal case: decrypt the encrypted profile key using the master key
            let master_key = self
                .master_key
                .ok_or_else(|| Error::Vault("Missing master key for decryption. Please authenticate first.".to_string()))?;
            let stretched_master_key = Self::stretch_master_key(&master_key)
                .map_err(|e| Error::Vault(format!("Failed to stretch master key: {}", e)))?;
            
            debug!("Decrypting profile key using master key");
            let decrypted_key = Self::decrypt_enc_string(key_enc, &stretched_master_key)
                .map_err(|e| Error::Vault(format!("Failed to decrypt profile key: {}. This usually means the master password is incorrect.", e)))?;
            
            debug!(
                "Decrypted profile key: {} bytes, first 16: {:02x?}",
                decrypted_key.len(),
                &decrypted_key[..std::cmp::min(16, decrypted_key.len())]
            );
            
            let key_bytes = Self::decode_key_bytes(&decrypted_key)
                .map_err(|e| Error::Vault(format!("Failed to decode user key bytes: {}", e)))?;
            
            debug!(
                "Decoded user key: {} bytes, enc first 8: {:02x?}, mac first 8: {:02x?}",
                key_bytes.len(),
                &key_bytes[..8],
                &key_bytes[32..40]
            );
            
            if key_bytes.len() != 64 {
                return Err(Error::Vault(format!(
                    "Invalid user key length: expected 64 bytes, got {}",
                    key_bytes.len()
                )));
            }
            
            SymmetricKey {
                enc_key: key_bytes[..32].to_vec(),
                mac_key: key_bytes[32..].to_vec(),
            }
        };
        
        self.user_key = Some(user_key);

        // Decrypt the user's RSA private key (needed for organization key decryption)
        if let Some(private_key_enc) = profile.get("privateKey").and_then(|v| v.as_str()) {
            debug!("Decrypting user's RSA private key");
            match Self::decrypt_private_key(private_key_enc, self.user_key.as_ref().unwrap()) {
                Ok(private_key) => {
                    debug!("Successfully decrypted RSA private key");
                    self.private_key = Some(private_key);
                }
                Err(e) => {
                    debug!("Failed to decrypt RSA private key: {} - organization items won't be decryptable", e);
                }
            }
        }

        // Decrypt organization keys
        if let Some(orgs) = profile.get("organizations") {
            if let Ok(organizations) = serde_json::from_value::<Vec<OrganizationResponse>>(orgs.clone()) {
                debug!("Found {} organizations", organizations.len());
                for org in organizations {
                    if let Some(ref org_key_enc) = org.key {
                        debug!("Decrypting key for organization: {}", org.id);
                        match self.decrypt_org_key(org_key_enc) {
                            Ok(org_key) => {
                                debug!("Successfully decrypted org key for: {}", org.id);
                                self.org_keys.insert(org.id.clone(), org_key);
                            }
                            Err(e) => {
                                debug!("Failed to decrypt org key for {}: {}", org.id, e);
                            }
                        }
                    }
                }
            }
        }

        if let Some(collections) = value.get("collections") {
            let collections: Vec<CollectionResponse> = serde_json::from_value(collections.clone())
                .map_err(|e| Error::Vault(format!("Failed to parse collections from sync: {}", e)))?;
            self.collections_cache = Some(collections);
        }

        let ciphers_value = value
            .get("ciphers")
            .ok_or_else(|| Error::Vault("Missing ciphers in sync response".to_string()))?;
        let ciphers: Vec<CipherResponse> = serde_json::from_value(ciphers_value.clone())
            .map_err(|e| Error::Vault(format!("Failed to parse ciphers from sync: {}", e)))?;

        // Decrypt ciphers - handle both personal and organization items
        let mut decrypted_ciphers = Vec::new();
        let mut skipped_count = 0;
        
        for mut cipher in ciphers {
            // Determine which key to use for decryption
            let decryption_key = if let Some(ref org_id) = cipher.organization_id {
                // Organization item - use org key
                if let Some(org_key) = self.org_keys.get(org_id) {
                    debug!("Decrypting organization cipher: {} (org_id: {})", cipher.id, org_id);
                    org_key
                } else {
                    debug!(
                        "Skipping organization cipher {} - no key available for org {}",
                        cipher.id, org_id
                    );
                    skipped_count += 1;
                    continue;
                }
            } else {
                // Personal item - use user key
                debug!("Decrypting personal cipher: {}", cipher.id);
                self.user_key.as_ref().unwrap()
            };
            
            let decrypted_name = self.decrypt_string_with_key(&cipher.name, decryption_key)?;
            cipher.name = decrypted_name;
            if let Some(ref notes) = cipher.notes {
                cipher.notes = Some(self.decrypt_string_with_key(notes, decryption_key)?);
            }
            if let Some(ref mut login) = cipher.login {
                if let Some(ref username) = login.username {
                    login.username = Some(self.decrypt_string_with_key(username, decryption_key)?);
                }
                if let Some(ref password) = login.password {
                    login.password = Some(self.decrypt_string_with_key(password, decryption_key)?);
                }
                if let Some(ref mut uris) = login.uris {
                    for uri in uris {
                        if let Some(ref uri_value) = uri.uri {
                            uri.uri = Some(self.decrypt_string_with_key(uri_value, decryption_key)?);
                        }
                    }
                }
            }
            decrypted_ciphers.push(cipher);
        }

        debug!(
            "Decrypted {} ciphers, skipped {} (no key available)",
            decrypted_ciphers.len(), skipped_count
        );

        for cipher in &decrypted_ciphers {
            debug!("Cipher name: {}", cipher.name);
        }

        Self::save_cache(&SyncCache {
            ciphers: decrypted_ciphers.clone(),
            collections: self.collections_cache.clone(),
        })?;

        Ok(decrypted_ciphers)
    }

    fn get_collections(&self) -> Result<Vec<CollectionResponse>> {
        let token = self
            .access_token
            .as_ref()
            .ok_or_else(|| Error::Vault("Not authenticated. Call authenticate() first.".to_string()))?;

        let base_url = self.config.vault_url.trim_end_matches('/');
        let url = if let Some(ref organization_id) = self.config.organization_id {
            format!("{}/api/organizations/{}/collections", base_url, organization_id)
        } else {
            format!("{}/api/collections", base_url)
        };

        let response = self
            .client
            .get(&url)
            .bearer_auth(token)
            .send()
            .map_err(|e| Error::Vault(format!("Failed to fetch collections: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().unwrap_or_else(|_| "Unknown error".to_string());
            return Err(Error::Vault(format!(
                "Failed to fetch collections with status {}: {}",
                status, text
            )));
        }

        let text = response
            .text()
            .map_err(|e| Error::Vault(format!("Failed to read collections response: {}", e)))?;

        let value: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| Error::Vault(format!("Failed to parse collections: {}. Response body: {}", e, text)))?;

        if value.is_array() {
            let collections: Vec<CollectionResponse> = serde_json::from_value(value)
                .map_err(|e| Error::Vault(format!("Failed to parse collections array: {}", e)))?;
            return Ok(collections);
        }

        if let Some(data) = value.get("data") {
            let collections: Vec<CollectionResponse> = serde_json::from_value(data.clone())
                .map_err(|e| Error::Vault(format!("Failed to parse collections data: {}", e)))?;
            return Ok(collections);
        }

        Err(Error::Vault(format!(
            "Failed to parse collections: unexpected response format. Response body: {}",
            text
        )))
    }

    fn expand_collection_ids(
        collections: &[CollectionResponse],
        base_ids: &[String],
    ) -> HashSet<String> {
        let mut children_map: HashMap<String, Vec<String>> = HashMap::new();
        for collection in collections {
            if let Some(ref parent_id) = collection.parent_id {
                children_map
                    .entry(parent_id.clone())
                    .or_default()
                    .push(collection.id.clone());
            }
        }

        let mut expanded: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<String> = base_ids.iter().cloned().collect();

        while let Some(current_id) = queue.pop_front() {
            if expanded.insert(current_id.clone()) {
                if let Some(children) = children_map.get(&current_id) {
                    for child in children {
                        queue.push_back(child.clone());
                    }
                }
            }
        }

        expanded
    }

    fn extract_ssh_entry(
        cipher: &CipherResponse,
        ssh_pattern: &Regex,
    ) -> Option<SshEntry> {
            if let Some(captures) = ssh_pattern.captures(&cipher.name) {
                if let (Some(user), Some(ip)) = (captures.get(1), captures.get(2)) {
                    let password = cipher
                        .login
                        .as_ref()
                        .and_then(|l| l.password.as_ref())
                        .cloned()
                        .unwrap_or_else(|| "".to_string());

                return Some(SshEntry {
                        user: user.as_str().to_string(),
                        ip: ip.as_str().to_string(),
                        password,
                    });
                }
            }

            if let Some(ref notes) = cipher.notes {
                if let Some(captures) = ssh_pattern.captures(notes) {
                    if let (Some(user), Some(ip)) = (captures.get(1), captures.get(2)) {
                        let password = cipher
                            .login
                            .as_ref()
                            .and_then(|l| l.password.as_ref())
                            .cloned()
                            .unwrap_or_else(|| "".to_string());

                    return Some(SshEntry {
                            user: user.as_str().to_string(),
                            ip: ip.as_str().to_string(),
                            password,
                        });
                    }
                }
            }

            if let Some(ref login_data) = cipher.login {
                if let Some(ref uris) = login_data.uris {
                    for uri_data in uris {
                        if let Some(ref uri) = uri_data.uri {
                            if let Some(captures) = ssh_pattern.captures(uri) {
                                if let (Some(user), Some(ip)) = (captures.get(1), captures.get(2)) {
                                    let password = login_data
                                        .password
                                        .as_ref()
                                        .cloned()
                                        .unwrap_or_else(|| "".to_string());

                                return Some(SshEntry {
                                        user: user.as_str().to_string(),
                                        ip: ip.as_str().to_string(),
                                        password,
                                    });
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn parse_ssh_entries(&self, ciphers: Vec<CipherResponse>) -> Result<Vec<SshEntry>> {
        // Pattern to match: ssh user@ip or ssh user@hostname
        let ssh_pattern = Regex::new(r"(?i)ssh\s+(\S+)@(\S+)").unwrap();
        let mut entries = Vec::new();

        let expanded_collection_ids = if let Some(ref collection_ids) = self.config.collection_ids {
            let collections = if let Some(ref cached) = self.collections_cache {
                cached.clone()
            } else {
                self.get_collections()?
            };
            let expanded = Self::expand_collection_ids(&collections, collection_ids);
            debug!(
                "Expanded collection IDs from {} to {}",
                collection_ids.len(),
                expanded.len()
            );
            Some(expanded)
        } else {
            None
        };

        for cipher in ciphers {
            // Filter by collection IDs if specified
            if let Some(ref expanded_ids) = expanded_collection_ids {
                if let Some(ref cipher_collections) = cipher.collection_ids {
                    if !cipher_collections.iter().any(|id| expanded_ids.contains(id)) {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            // Filter by organization ID if specified
            if let Some(ref organization_id) = self.config.organization_id {
                if cipher.organization_id.as_ref() != Some(organization_id) {
                    continue;
                }
            }

            if let Some(entry) = Self::extract_ssh_entry(&cipher, &ssh_pattern) {
                entries.push(entry);
            }
        }

        Ok(entries)
    }
}

impl VaultApi for RealVaultApi {
    fn authenticate(&mut self, email: String, password: String) -> Result<()> {
        self.email = Some(email);
        self.password = Some(password);
        self.login()
    }

    fn search(&mut self, pattern: &str) -> Result<Vec<SshEntry>> {
        // Ensure we're authenticated unless cache exists
        if self.access_token.is_none() && !Self::cache_exists() {
            return Err(Error::Vault(
                "Not authenticated. Call authenticate() first.".to_string(),
            ));
        }

        let ciphers = self.get_ciphers()?;
        debug!("Fetched {} ciphers from vault", ciphers.len());
        let mut entries = self.parse_ssh_entries(ciphers)?;
        debug!("Matched {} SSH entries from all ciphers", entries.len());

        // Filter by pattern
        if !pattern.is_empty() {
            entries.retain(|e| e.matches_pattern(pattern));
            debug!("Matched {} SSH entries after pattern filter", entries.len());
        }

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_pattern_matching() {
        let pattern = Regex::new(r"(?i)ssh\s+(\S+)@(\S+)").unwrap();
        
        assert!(pattern.is_match("ssh admin@192.168.1.1"));
        assert!(pattern.is_match("SSH root@10.0.0.1"));
        assert!(pattern.is_match("ssh user@example.com"));
        
        if let Some(captures) = pattern.captures("ssh admin@192.168.1.1") {
            assert_eq!(captures.get(1).unwrap().as_str(), "admin");
            assert_eq!(captures.get(2).unwrap().as_str(), "192.168.1.1");
        }
    }

    #[test]
    fn test_extract_ssh_entry_from_name() {
        let cipher = CipherResponse {
            id: "1".to_string(),
            cipher_type: 1,
            name: "ssh root@10.0.0.1".to_string(),
            notes: None,
            login: Some(LoginData {
                username: Some("root".to_string()),
                password: Some("secret".to_string()),
                uris: None,
            }),
            collection_ids: None,
            organization_id: None,
            _other: HashMap::new(),
        };

        let pattern = Regex::new(r"(?i)ssh\s+(\S+)@(\S+)").unwrap();
        let entry = RealVaultApi::extract_ssh_entry(&cipher, &pattern).unwrap();
        assert_eq!(entry.user, "root");
        assert_eq!(entry.ip, "10.0.0.1");
        assert_eq!(entry.password, "secret");
    }

    #[test]
    fn test_extract_ssh_entry_from_notes() {
        let cipher = CipherResponse {
            id: "2".to_string(),
            cipher_type: 1,
            name: "Server".to_string(),
            notes: Some("ssh deploy@172.16.0.2".to_string()),
            login: Some(LoginData {
                username: Some("deploy".to_string()),
                password: Some("deploypass".to_string()),
                uris: None,
            }),
            collection_ids: None,
            organization_id: None,
            _other: HashMap::new(),
        };

        let pattern = Regex::new(r"(?i)ssh\s+(\S+)@(\S+)").unwrap();
        let entry = RealVaultApi::extract_ssh_entry(&cipher, &pattern).unwrap();
        assert_eq!(entry.user, "deploy");
        assert_eq!(entry.ip, "172.16.0.2");
        assert_eq!(entry.password, "deploypass");
    }

    #[test]
    fn test_extract_ssh_entry_from_uri() {
        let cipher = CipherResponse {
            id: "3".to_string(),
            cipher_type: 1,
            name: "Server".to_string(),
            notes: None,
            login: Some(LoginData {
                username: None,
                password: Some("uripass".to_string()),
                uris: Some(vec![UriData {
                    uri: Some("ssh admin@192.168.1.10".to_string()),
                }]),
            }),
            collection_ids: None,
            organization_id: None,
            _other: HashMap::new(),
        };

        let pattern = Regex::new(r"(?i)ssh\s+(\S+)@(\S+)").unwrap();
        let entry = RealVaultApi::extract_ssh_entry(&cipher, &pattern).unwrap();
        assert_eq!(entry.user, "admin");
        assert_eq!(entry.ip, "192.168.1.10");
        assert_eq!(entry.password, "uripass");
    }

    #[test]
    fn test_expand_collection_ids_includes_descendants() {
        let collections = vec![
            CollectionResponse {
                id: "base".to_string(),
                name: "Base".to_string(),
                organization_id: Some("org".to_string()),
                parent_id: None,
                _other: HashMap::new(),
            },
            CollectionResponse {
                id: "child".to_string(),
                name: "Child".to_string(),
                organization_id: Some("org".to_string()),
                parent_id: Some("base".to_string()),
                _other: HashMap::new(),
            },
            CollectionResponse {
                id: "grandchild".to_string(),
                name: "Grandchild".to_string(),
                organization_id: Some("org".to_string()),
                parent_id: Some("child".to_string()),
                _other: HashMap::new(),
            },
        ];

        let expanded = RealVaultApi::expand_collection_ids(&collections, &vec!["base".to_string()]);
        assert!(expanded.contains("base"));
        assert!(expanded.contains("child"));
        assert!(expanded.contains("grandchild"));
    }
}

