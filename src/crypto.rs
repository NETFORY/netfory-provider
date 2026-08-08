//! Криптографическое ядро провайдера.
//!
//! Идея «единого корня»: из одной BIP-39 мнемоники мы детерминированно
//! получаем 32-байтный корневой ключ (seed[..32]). Этот корень служит
//! ОДНОВРЕМЕННО:
//!   * приватным ключом Iroh (определяет NodeID/PeerID — P2P-паспорт ноды);
//!   * приватным ключом Ed25519 для подписи JSON-ответов (Data Signing).
//!
//! Поскольку и Iroh, и наша подпись используют Ed25519, публичный ключ
//! (= NodeID) и ключ верификации подписи — это ОДНИ И ТЕ ЖЕ 32 байта.
//! Клиент, зная `api://<NodeID>`, может проверить подпись ответа без
//! какого-либо дополнительного обмена ключами.

use anyhow::{anyhow, Result};
use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Корневой 32-байтный материал ключа, выведенный из мнемоники.
pub type Root = [u8; 32];

/// Сгенерировать новую валидную мнемонику BIP-39 на 12 слов.
pub fn generate_mnemonic() -> Result<String> {
    let m = Mnemonic::generate_in(Language::English, 12)
        .map_err(|e| anyhow!("генерация мнемоники: {e}"))?;
    Ok(m.to_string())
}

/// Вывести детерминированный 32-байтный корень из мнемоники.
/// Берём первые 32 байта стандартного BIP-39 seed (PBKDF2, пустой пароль).
pub fn root_from_mnemonic(mnemonic: &str) -> Result<Root> {
    let m = Mnemonic::parse_in_normalized(Language::English, mnemonic.trim())
        .map_err(|e| anyhow!("разбор мнемоники: {e}"))?;
    let seed = m.to_seed(""); // [u8; 64]
    let mut root = [0u8; 32];
    root.copy_from_slice(&seed[..32]);
    Ok(root)
}

/// Секретный ключ Iroh из корня (тот же материал — тот же NodeID).
pub fn iroh_secret(root: &Root) -> iroh::SecretKey {
    iroh::SecretKey::from_bytes(root)
}

/// Ed25519 SigningKey из того же корня (для подписи данных).
pub fn signing_key(root: &Root) -> SigningKey {
    SigningKey::from_bytes(root)
}

/// Подписать произвольное сообщение, вернуть подпись в hex.
pub fn sign_hex(sk: &SigningKey, msg: &[u8]) -> String {
    let sig: Signature = sk.sign(msg);
    hex::encode(sig.to_bytes())
}

/// Проверить hex-подпись по NodeID (строка Iroh EndpointId == Ed25519 pubkey).
/// Используется клиентом; здесь — для самопроверки и тестов.
pub fn verify_hex(node_id_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
    let pk_bytes = match hex::decode(node_id_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pk_bytes);
    let vk = match VerifyingKey::from_bytes(&arr) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };
    let mut sarr = [0u8; 64];
    sarr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sarr);
    vk.verify(msg, &sig).is_ok()
}
