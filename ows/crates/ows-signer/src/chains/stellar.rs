use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ows_core::ChainType;
use sha2::{Digest, Sha256};

/// Stellar chain signer (Ed25519, StrKey G-addresses).
///
/// Implements the Stellar signing protocol:
/// - Address derivation via StrKey encoding (SEP-0023)
/// - Transaction signing with SHA-256 preimage (network ID || envelope type || tx body)
/// - XDR TransactionEnvelope construction for broadcasting
/// - HD derivation path `m/44'/148'/{index}'` (SEP-0005 / SLIP-10)
pub struct StellarSigner;

// ---------------------------------------------------------------------------
// SEP-0023 StrKey constants
// ---------------------------------------------------------------------------

/// SEP-0023: ED25519_PUBLIC_KEY version byte = type_id(6) << 3 = 48 (0x30).
const STRKEY_VERSION_ED25519_PUBLIC: u8 = 6 << 3; // 48 (0x30)

/// RFC 4648 Base32 alphabet (no padding).
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// ---------------------------------------------------------------------------
// Stellar network constants
// ---------------------------------------------------------------------------

/// SHA-256 hash of the pubnet passphrase "Public Global Stellar Network ; September 2015".
/// Pre-computed network ID for transaction signing preimage construction.
#[cfg(test)]
const PUBNET_NETWORK_ID: [u8; 32] = [
    0x7a, 0xc3, 0x39, 0x97, 0x54, 0x4e, 0x31, 0x75, // SHA-256 of pubnet passphrase
    0xd2, 0x66, 0xbd, 0x02, 0x24, 0x39, 0xb2, 0x2c, 0xdb, 0x16, 0x50, 0x8c, 0x01, 0x16, 0x3f, 0x26,
    0xe5, 0xcb, 0x2a, 0x3e, 0x10, 0x45, 0xa9, 0x79,
];

/// XDR ENVELOPE_TYPE_TX = 2, encoded as 4-byte big-endian.
/// Used in the signing preimage for standard v1 transactions (classic and Soroban).
const ENVELOPE_TYPE_TX: [u8; 4] = [0x00, 0x00, 0x00, 0x02];

/// Envelope type for Soroban authorization entry signing.
/// Used by `sign_auth_entry` for Soroban-specific signing contexts.
const ENVELOPE_TYPE_SOROBAN_AUTHORIZATION: u32 = 29;

/// Stellar public network (pubnet) passphrase.
/// Used by `compute_stellar_hash` when a string passphrase is needed.
const NETWORK_PASSPHRASE_PUBNET: &str = "Public Global Stellar Network ; September 2015";

/// Stellar test network (testnet) passphrase.
/// Defined for completeness; not used until multi-network support is added.
#[allow(dead_code)]
const NETWORK_PASSPHRASE_TESTNET: &str = "Test SDF Network ; September 2015";

// ---------------------------------------------------------------------------
// SLIP-44 / SEP-0005
// ---------------------------------------------------------------------------

/// SLIP-44 coin type for Stellar (registered as 148).
const STELLAR_COIN_TYPE: u32 = 148;

// ---------------------------------------------------------------------------
// CRC-16-XMODEM (same algorithm as TON's crc16_ccitt in ton.rs)
// ---------------------------------------------------------------------------

/// Compute CRC-16-XMODEM checksum.
///
/// Parameters (CRC-16/XMODEM):
/// - Polynomial: `0x1021` (x^16 + x^12 + x^5 + 1)
/// - Initial value: `0x0000`
/// - Input/output reflection: none
/// - Final XOR: `0x0000`
///
/// Standard check value: `crc16_xmodem(b"123456789") == 0x31C3`.
fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000; // CRC-16-XMODEM initial value
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021; // CRC-16-XMODEM polynomial
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ---------------------------------------------------------------------------
// RFC 4648 Base32 encoder (no padding)
// ---------------------------------------------------------------------------

/// Encode bytes as RFC 4648 Base32 (no padding).
///
/// For StrKey's 35-byte input, 280 bits / 5 = exactly 56 characters with no
/// remainder, so the trailing-bits branch never executes. It is present for
/// correctness in the general case.
fn base32_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u64 = 0;
    let mut bits_left: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1F) as usize;
            result.push(BASE32_ALPHABET[index] as char); // RFC 4648 alphabet
        }
    }
    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        result.push(BASE32_ALPHABET[index] as char);
    }
    result
}

// ---------------------------------------------------------------------------
// SEP-0023 StrKey encoding
// ---------------------------------------------------------------------------

/// Encode a 32-byte Ed25519 public key as a Stellar StrKey G-address (SEP-0023).
///
/// Layout:
/// 1. Payload = version_byte(1) || public_key(32) = 33 bytes
/// 2. Checksum = CRC-16-XMODEM(payload), appended in little-endian (2 bytes)
/// 3. Encode payload || checksum_le (35 bytes) as RFC 4648 Base32 (no padding)
/// 4. Result: always 56 characters, always starts with 'G'
fn strkey_encode(version_byte: u8, key: &[u8; 32]) -> String {
    // SEP-0023: payload = version_byte || raw_public_key
    let mut blob = Vec::with_capacity(35); // 33 payload + 2 checksum
    blob.push(version_byte);
    blob.extend_from_slice(key);

    // SEP-0023: CRC-16-XMODEM checksum, appended in little-endian order
    let crc = crc16_xmodem(&blob);
    blob.push(crc as u8); // low byte first (little-endian)
    blob.push((crc >> 8) as u8); // high byte second

    // RFC 4648 Base32, no padding; 35 bytes -> exactly 56 characters
    base32_encode(&blob)
}

// ---------------------------------------------------------------------------
// Signing preimage helper (Soroban-ready shared primitive)
// ---------------------------------------------------------------------------

/// Compute the Stellar signing preimage hash.
///
/// The preimage is: SHA-256(network_id_hash || envelope_type_tag || body)
/// where:
/// - network_id_hash = SHA-256(network_passphrase)
/// - envelope_type_tag = envelope_type as 4-byte big-endian u32
/// - body = the XDR-encoded body bytes (transaction or auth entry)
///
/// This is the shared primitive for all Stellar signing contexts:
/// - Transaction signing uses envelope_type = 2 (ENVELOPE_TYPE_TX)
/// - Soroban auth entry signing uses envelope_type = 29 (ENVELOPE_TYPE_SOROBAN_AUTHORIZATION)
fn compute_stellar_hash(network_passphrase: &str, envelope_type: u32, body: &[u8]) -> [u8; 32] {
    let network_id_hash = Sha256::digest(network_passphrase.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(network_id_hash);
    hasher.update(envelope_type.to_be_bytes());
    hasher.update(body);
    hasher.finalize().into()
}

impl StellarSigner {
    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        let key_bytes: [u8; 32] = private_key.try_into().map_err(|_| {
            SignerError::InvalidPrivateKey(format!("expected 32 bytes, got {}", private_key.len()))
        })?;
        Ok(SigningKey::from_bytes(&key_bytes))
    }
}

impl ChainSigner for StellarSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Stellar
    }

    fn curve(&self) -> Curve {
        Curve::Ed25519
    }

    fn coin_type(&self) -> u32 {
        STELLAR_COIN_TYPE // SLIP-44: 148
    }

    /// Derive a Stellar G-address from a 32-byte Ed25519 private key.
    ///
    /// Uses SEP-0023 StrKey encoding with ED25519_PUBLIC_KEY version byte (0x30).
    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        Ok(strkey_encode(
            STRKEY_VERSION_ED25519_PUBLIC, // SEP-0023: 6 << 3 = 48 (0x30)
            verifying_key.as_bytes(),
        ))
    }

    /// Raw Ed25519 signing of arbitrary bytes.
    ///
    /// Returns the 64-byte Ed25519 signature with `public_key: None`,
    /// matching the Solana/TON/Sui pattern for Ed25519 chains.
    /// Note: `sign_transaction` returns `public_key: Some(...)` because
    /// `encode_signed_transaction` needs it for the DecoratedSignature hint.
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let signature = signing_key.sign(message);
        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: None,
        })
    }

    /// Sign a Stellar transaction.
    ///
    /// Constructs the signing preimage per the Stellar protocol:
    /// ```text
    /// preimage = network_id_hash(32) || ENVELOPE_TYPE_TX(4) || tx_body_xdr
    /// digest   = SHA-256(preimage)
    /// signature = Ed25519_sign(private_key, digest)
    /// ```
    ///
    /// The `tx_bytes` parameter is the raw XDR-encoded Transaction body (NOT
    /// including any envelope wrapper). The network defaults to pubnet.
    ///
    /// Works for both classic and Soroban transactions -- Soroban txs use
    /// the same TransactionEnvelope signing flow with ENVELOPE_TYPE_TX = 2.
    fn sign_transaction(
        &self,
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        let signing_key = Self::signing_key(private_key)?;

        // Use compute_stellar_hash -- the shared primitive that also supports
        // Soroban auth entry signing (envelope type 29) via sign_auth_entry.
        let digest = compute_stellar_hash(NETWORK_PASSPHRASE_PUBNET, 2, tx_bytes);

        let signature = signing_key.sign(&digest);
        let verifying_key = signing_key.verifying_key();
        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: Some(verifying_key.as_bytes().to_vec()),
        })
    }

    /// Sign an arbitrary message with raw Ed25519 (no prefix, no hashing).
    ///
    /// Consistent with the Solana/Sui pattern for Ed25519 chains.
    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        self.sign(private_key, message)
    }

    /// Encode a signed transaction as an XDR TransactionEnvelope (v1).
    ///
    /// Wire format:
    /// ```text
    /// [0x00,0x00,0x00,0x02]   // ENVELOPE_TYPE_TX discriminant (4 bytes)
    /// || tx_bytes              // Transaction body XDR (pass-through)
    /// || [0x00,0x00,0x00,0x01] // signatures array length = 1 (4 bytes)
    /// || hint[4]               // SignatureHint: last 4 bytes of public key (opaque[4])
    /// || [0x00,0x00,0x00,0x40] // signature opaque length = 64 (4 bytes)
    /// || signature[64]         // Ed25519 signature bytes
    /// ```
    ///
    /// Total overhead: 4 + 4 + 4 + 4 + 64 = 80 bytes around tx_bytes.
    fn encode_signed_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &SignOutput,
    ) -> Result<Vec<u8>, SignerError> {
        if signature.signature.len() != 64 {
            return Err(SignerError::InvalidTransaction(
                "expected 64-byte Ed25519 signature".into(),
            ));
        }
        let pubkey = signature.public_key.as_ref().ok_or_else(|| {
            SignerError::InvalidTransaction(
                "Stellar encode_signed_transaction requires public_key in SignOutput".into(),
            )
        })?;
        if pubkey.len() != 32 {
            return Err(SignerError::InvalidTransaction(
                "expected 32-byte public key".into(),
            ));
        }

        // XDR TransactionEnvelope (v1)
        let mut env = Vec::with_capacity(tx_bytes.len() + 80); // tx + 80 bytes overhead

        // Discriminant: ENVELOPE_TYPE_TX = 2 (4 bytes, big-endian)
        env.extend_from_slice(&ENVELOPE_TYPE_TX);

        // Transaction body XDR (pass-through)
        env.extend_from_slice(tx_bytes);

        // Signatures array: length = 1 (XDR variable-length array, 4 bytes big-endian)
        env.extend_from_slice(&1u32.to_be_bytes());

        // DecoratedSignature.hint: last 4 bytes of public key (opaque[4], no length prefix)
        env.extend_from_slice(&pubkey[28..32]);

        // DecoratedSignature.signature: opaque<64> (4-byte length prefix + 64 bytes data)
        env.extend_from_slice(&64u32.to_be_bytes()); // 0x00000040
        env.extend_from_slice(&signature.signature);

        Ok(env)
    }

    /// Returns the SEP-0005 / SLIP-10 derivation path for Stellar.
    ///
    /// Path: `m/44'/148'/{index}'` -- all components hardened, 3 levels deep.
    /// Identical in structure to TON's `m/44'/607'/{index}'`.
    /// Sign a Soroban authorization entry.
    ///
    /// Uses `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION` (29) in the signing preimage
    /// instead of `ENVELOPE_TYPE_TX` (2). The `auth_entry` should be the
    /// XDR-encoded `HashIdPreimage` body for the authorization.
    fn sign_auth_entry(
        &self,
        private_key: &[u8],
        auth_entry: &[u8],
    ) -> Result<SignOutput, SignerError> {
        let signing_key = StellarSigner::signing_key(private_key)?;
        let digest = compute_stellar_hash(
            NETWORK_PASSPHRASE_PUBNET,
            ENVELOPE_TYPE_SOROBAN_AUTHORIZATION,
            auth_entry,
        );
        let signature = signing_key.sign(&digest);
        let verifying_key = signing_key.verifying_key();
        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: Some(verifying_key.as_bytes().to_vec()),
        })
    }

    fn default_derivation_path(&self, index: u32) -> String {
        format!("m/44'/148'/{}'", index) // SEP-0005: m/44'/148'/index'
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    /// RFC 8032 Test Vector 1 private key (32-byte seed).
    const TEST_KEY_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

    /// RFC 8032 Test Vector 1 public key (32 bytes).
    const TEST_PUBKEY_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn test_privkey() -> Vec<u8> {
        hex::decode(TEST_KEY_HEX).unwrap()
    }

    // ---------------------------------------------------------------
    // CRC-16-XMODEM
    // ---------------------------------------------------------------

    #[test]
    fn test_crc16_xmodem_check_value() {
        // Standard CRC-16/XMODEM check value
        assert_eq!(crc16_xmodem(b"123456789"), 0x31C3);
    }

    #[test]
    fn test_crc16_xmodem_spec_vector_1() {
        // Spec test vector 1: CRC of payload for RFC 8032 TV1 public key
        let payload =
            hex::decode("30d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();
        assert_eq!(crc16_xmodem(&payload), 0x919e); // Computed CRC for RFC 8032 TV1 payload
    }

    #[test]
    fn test_crc16_xmodem_spec_vector_2() {
        // Spec test vector 2: CRC of payload for all-zero public key
        let payload =
            hex::decode("300000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        assert_eq!(crc16_xmodem(&payload), 0xe558); // Computed CRC for all-zero payload
    }

    // ---------------------------------------------------------------
    // Base32 encoding
    // ---------------------------------------------------------------

    #[test]
    fn test_base32_encode_rfc_vectors() {
        // RFC 4648 test vectors (without padding)
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    // ---------------------------------------------------------------
    // StrKey address encoding (SEP-0023)
    // ---------------------------------------------------------------

    #[test]
    fn test_strkey_known_address_rfc8032_tv1() {
        // Spec test vector 1: RFC 8032 Test Vector 1 key pair
        let pubkey: [u8; 32] = hex::decode(TEST_PUBKEY_HEX).unwrap().try_into().unwrap();
        let addr = strkey_encode(STRKEY_VERSION_ED25519_PUBLIC, &pubkey);
        assert_eq!(
            addr,
            "GDLVVGABQKYQVN6VJP7NHSLEA45A5YLS6PNKMIZFV4BBU2HXA5IRVHUR"
        );
        assert_eq!(addr.len(), 56); // Always 56 characters
        assert!(addr.starts_with('G')); // Always starts with G
    }

    #[test]
    fn test_strkey_all_zero_key() {
        // Spec test vector 2: all-zero public key
        let pubkey = [0u8; 32];
        let addr = strkey_encode(STRKEY_VERSION_ED25519_PUBLIC, &pubkey);
        assert_eq!(
            addr,
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
        );
        assert_eq!(addr.len(), 56);
        assert!(addr.starts_with('G'));
    }

    #[test]
    fn test_strkey_sdf_root_account() {
        // Spec test vector 3: SDF root account
        let pubkey: [u8; 32] =
            hex::decode("3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a")
                .unwrap()
                .try_into()
                .unwrap();
        let addr = strkey_encode(STRKEY_VERSION_ED25519_PUBLIC, &pubkey);
        assert_eq!(
            addr,
            "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"
        );
    }

    // ---------------------------------------------------------------
    // Address derivation from private key
    // ---------------------------------------------------------------

    #[test]
    fn test_derive_address_format() {
        let signer = StellarSigner;
        let addr = signer.derive_address(&test_privkey()).unwrap();
        assert!(
            addr.starts_with('G'),
            "StrKey address must start with G, got: {addr}"
        );
        assert_eq!(addr.len(), 56, "StrKey address must be exactly 56 chars");
    }

    #[test]
    fn test_derive_address_known_value() {
        // RFC 8032 Test Vector 1 private key -> known G-address
        let signer = StellarSigner;
        let addr = signer.derive_address(&test_privkey()).unwrap();
        assert_eq!(
            addr,
            "GDLVVGABQKYQVN6VJP7NHSLEA45A5YLS6PNKMIZFV4BBU2HXA5IRVHUR"
        );
    }

    #[test]
    fn test_derive_address_deterministic() {
        let signer = StellarSigner;
        let a1 = signer.derive_address(&test_privkey()).unwrap();
        let a2 = signer.derive_address(&test_privkey()).unwrap();
        assert_eq!(a1, a2, "address derivation must be deterministic");
    }

    // ---------------------------------------------------------------
    // Chain properties
    // ---------------------------------------------------------------

    #[test]
    fn test_chain_properties() {
        let signer = StellarSigner;
        assert_eq!(signer.chain_type(), ChainType::Stellar);
        assert_eq!(signer.curve(), Curve::Ed25519);
        assert_eq!(signer.coin_type(), 148); // SLIP-44: Stellar = 148
    }

    #[test]
    fn test_derivation_path() {
        let signer = StellarSigner;
        assert_eq!(signer.default_derivation_path(0), "m/44'/148'/0'"); // SEP-0005
        assert_eq!(signer.default_derivation_path(1), "m/44'/148'/1'");
        assert_eq!(signer.default_derivation_path(5), "m/44'/148'/5'");
    }

    // ---------------------------------------------------------------
    // Signing: raw Ed25519
    // ---------------------------------------------------------------

    #[test]
    fn test_sign_raw_ed25519() {
        let signer = StellarSigner;
        let privkey = test_privkey();
        let message = b"test stellar message";

        let result = signer.sign(&privkey, message).unwrap();
        assert_eq!(
            result.signature.len(),
            64,
            "Ed25519 signature must be 64 bytes"
        );
        assert!(result.recovery_id.is_none(), "Ed25519 has no recovery ID");
        assert!(
            result.public_key.is_none(),
            "sign() returns None for public_key (matching Solana/TON pattern)"
        );

        // Verify the signature with ed25519-dalek
        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key
            .verify(message, &sig)
            .expect("signature should verify");
    }

    #[test]
    fn test_sign_deterministic() {
        let signer = StellarSigner;
        let privkey = test_privkey();
        let msg = b"deterministic test";

        // Ed25519 signing is deterministic (RFC 8032)
        let s1 = signer.sign(&privkey, msg).unwrap();
        let s2 = signer.sign(&privkey, msg).unwrap();
        assert_eq!(s1.signature, s2.signature);
    }

    // ---------------------------------------------------------------
    // Message signing
    // ---------------------------------------------------------------

    #[test]
    fn test_sign_message_is_raw_ed25519() {
        let signer = StellarSigner;
        let privkey = test_privkey();
        let msg = b"hello stellar";

        // sign_message delegates to sign (no prefix, no hashing)
        let from_sign = signer.sign(&privkey, msg).unwrap();
        let from_sign_message = signer.sign_message(&privkey, msg).unwrap();
        assert_eq!(from_sign.signature, from_sign_message.signature);
    }

    // ---------------------------------------------------------------
    // Transaction signing
    // ---------------------------------------------------------------

    #[test]
    fn test_sign_transaction_preimage_construction() {
        let signer = StellarSigner;
        let privkey = test_privkey();
        let tx_body = hex::decode("deadbeef").unwrap();

        let result = signer.sign_transaction(&privkey, &tx_body).unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.public_key.is_some());

        // Manually construct the expected preimage
        let mut expected_preimage = Vec::new();
        expected_preimage.extend_from_slice(&PUBNET_NETWORK_ID); // 32 bytes
        expected_preimage.extend_from_slice(&ENVELOPE_TYPE_TX); // 4 bytes
        expected_preimage.extend_from_slice(&tx_body); // 4 bytes
        assert_eq!(expected_preimage.len(), 40); // 32 + 4 + 4

        // Verify: full preimage matches spec test vector
        assert_eq!(
            hex::encode(&expected_preimage),
            "7ac33997544e3175d266bd022439b22cdb16508c01163f26e5cb2a3e1045a97900000002deadbeef"
        );

        // The digest via compute_stellar_hash should match SHA-256(preimage)
        let digest_via_helper = compute_stellar_hash(NETWORK_PASSPHRASE_PUBNET, 2, &tx_body);
        let digest: [u8; 32] = Sha256::digest(&expected_preimage).into();
        assert_eq!(
            digest_via_helper, digest,
            "compute_stellar_hash must match manual preimage"
        );

        // Verify the signature is over the correct digest
        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key
            .verify(&digest, &sig)
            .expect("signature should verify against SHA-256(preimage)");
    }

    #[test]
    fn test_sign_transaction_differs_from_raw_sign() {
        let signer = StellarSigner;
        let privkey = test_privkey();
        let tx = b"some transaction data";

        // sign_transaction hashes with preimage; sign does not
        let tx_result = signer.sign_transaction(&privkey, tx).unwrap();
        let raw_result = signer.sign(&privkey, tx).unwrap();
        assert_ne!(tx_result.signature, raw_result.signature);
    }

    #[test]
    fn test_sign_transaction_deterministic() {
        let signer = StellarSigner;
        let privkey = test_privkey();
        let tx = b"deterministic tx";

        let s1 = signer.sign_transaction(&privkey, tx).unwrap();
        let s2 = signer.sign_transaction(&privkey, tx).unwrap();
        assert_eq!(s1.signature, s2.signature);
    }

    #[test]
    fn test_sign_transaction_hint_bytes() {
        // Verify the signature hint is the last 4 bytes of the public key
        let signer = StellarSigner;
        let privkey = test_privkey();
        let pubkey = hex::decode(TEST_PUBKEY_HEX).unwrap();
        let expected_hint = &pubkey[28..32]; // last 4 bytes: f7 07 51 1a
        assert_eq!(hex::encode(expected_hint), "f707511a"); // Spec test vector

        let result = signer.sign_transaction(&privkey, b"tx").unwrap();
        let actual_pubkey = result.public_key.as_ref().unwrap();
        assert_eq!(&actual_pubkey[28..32], expected_hint);
    }

    // ---------------------------------------------------------------
    // Envelope encoding (XDR TransactionEnvelope v1)
    // ---------------------------------------------------------------

    #[test]
    fn test_encode_signed_transaction_format() {
        let signer = StellarSigner;
        let privkey = test_privkey();
        let tx_body = vec![0xAA; 100]; // 100-byte fake transaction body

        let result = signer.sign_transaction(&privkey, &tx_body).unwrap();
        let envelope = signer.encode_signed_transaction(&tx_body, &result).unwrap();

        // Total: 4 (discriminant) + 100 (tx) + 4 (sig count) + 4 (hint)
        //        + 4 (sig length) + 64 (sig) = 180 bytes
        assert_eq!(envelope.len(), 100 + 80);

        // Discriminant: ENVELOPE_TYPE_TX = 2
        assert_eq!(&envelope[0..4], &[0x00, 0x00, 0x00, 0x02]);

        // Transaction body at offset 4..104
        assert_eq!(&envelope[4..104], &tx_body[..]);

        // Signatures array length = 1
        assert_eq!(&envelope[104..108], &[0x00, 0x00, 0x00, 0x01]);

        // Signature hint = last 4 bytes of public key
        let pubkey = result.public_key.as_ref().unwrap();
        assert_eq!(&envelope[108..112], &pubkey[28..32]);

        // Signature opaque length = 64
        assert_eq!(&envelope[112..116], &[0x00, 0x00, 0x00, 0x40]); // 64 decimal

        // Signature bytes
        assert_eq!(&envelope[116..180], &result.signature[..]);
    }

    #[test]
    fn test_encode_signed_transaction_rejects_bad_sig_length() {
        let signer = StellarSigner;
        let bad_output = SignOutput {
            signature: vec![0u8; 32], // wrong: should be 64
            recovery_id: None,
            public_key: Some(vec![0u8; 32]),
        };
        assert!(signer
            .encode_signed_transaction(b"tx", &bad_output)
            .is_err());
    }

    #[test]
    fn test_encode_signed_transaction_rejects_missing_pubkey() {
        let signer = StellarSigner;
        let bad_output = SignOutput {
            signature: vec![0u8; 64],
            recovery_id: None,
            public_key: None, // missing
        };
        assert!(signer
            .encode_signed_transaction(b"tx", &bad_output)
            .is_err());
    }

    #[test]
    fn test_encode_signed_transaction_rejects_bad_pubkey_length() {
        let signer = StellarSigner;
        let bad_output = SignOutput {
            signature: vec![0u8; 64],
            recovery_id: None,
            public_key: Some(vec![0u8; 16]), // wrong: should be 32
        };
        assert!(signer
            .encode_signed_transaction(b"tx", &bad_output)
            .is_err());
    }

    // ---------------------------------------------------------------
    // Full pipeline
    // ---------------------------------------------------------------

    #[test]
    fn test_full_signing_pipeline() {
        let signer = StellarSigner;
        let privkey = test_privkey();
        let tx_body = b"full_pipeline_stellar_tx";

        // 1. extract_signable_bytes (default: identity)
        let signable = signer.extract_signable_bytes(tx_body).unwrap();
        assert_eq!(signable, tx_body);

        // 2. sign_transaction
        let output = signer.sign_transaction(&privkey, signable).unwrap();
        assert_eq!(output.signature.len(), 64);
        assert!(output.public_key.is_some());

        // 3. encode_signed_transaction
        let envelope = signer.encode_signed_transaction(tx_body, &output).unwrap();

        // 4. Verify envelope structure
        assert_eq!(&envelope[0..4], &ENVELOPE_TYPE_TX); // discriminant
        assert_eq!(&envelope[4..4 + tx_body.len()], tx_body); // tx body

        // Verify signature is valid using compute_stellar_hash
        let pubkey_bytes = output.public_key.as_ref().unwrap();
        let verifying_key =
            VerifyingKey::from_bytes(&pubkey_bytes.clone().try_into().unwrap()).unwrap();

        let digest = compute_stellar_hash(NETWORK_PASSPHRASE_PUBNET, 2, tx_body);

        let sig = ed25519_dalek::Signature::from_bytes(&output.signature.try_into().unwrap());
        verifying_key
            .verify(&digest, &sig)
            .expect("full pipeline signature should verify");
    }

    // ---------------------------------------------------------------
    // Error handling
    // ---------------------------------------------------------------

    #[test]
    fn test_invalid_private_key_length() {
        let signer = StellarSigner;
        let bad_key = vec![0u8; 16]; // too short
        assert!(signer.derive_address(&bad_key).is_err());
        assert!(signer.sign(&bad_key, b"msg").is_err());
        assert!(signer.sign_transaction(&bad_key, b"tx").is_err());
        assert!(signer.sign_message(&bad_key, b"msg").is_err());
    }

    // ---------------------------------------------------------------
    // Network ID verification
    // ---------------------------------------------------------------

    #[test]
    fn test_pubnet_network_id() {
        // Verify the pre-computed network ID matches SHA-256 of the passphrase
        let passphrase = b"Public Global Stellar Network ; September 2015";
        let computed: [u8; 32] = Sha256::digest(passphrase).into();
        assert_eq!(computed, PUBNET_NETWORK_ID);
    }

    #[test]
    fn test_testnet_network_id() {
        // Verify the testnet passphrase produces the expected hash (for reference)
        let passphrase = b"Test SDF Network ; September 2015";
        let computed = Sha256::digest(passphrase);
        assert_eq!(
            hex::encode(computed),
            "cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472"
        );
    }

    // ---------------------------------------------------------------
    // StrKey checksum self-consistency
    // ---------------------------------------------------------------

    #[test]
    fn test_strkey_checksum_self_consistency() {
        // Derive address and verify CRC-16 checksum independently
        let signing_key = SigningKey::from_bytes(&test_privkey().try_into().unwrap());
        let vk = signing_key.verifying_key();

        let mut payload = vec![STRKEY_VERSION_ED25519_PUBLIC];
        payload.extend_from_slice(vk.as_bytes());
        let crc = crc16_xmodem(&payload);
        payload.push(crc as u8);
        payload.push((crc >> 8) as u8);

        let expected = base32_encode(&payload);
        let actual = StellarSigner.derive_address(&test_privkey()).unwrap();
        assert_eq!(actual, expected);
    }

    // ---------------------------------------------------------------
    // compute_stellar_hash tests
    // ---------------------------------------------------------------

    #[test]
    fn test_compute_stellar_hash_deterministic() {
        let h1 = compute_stellar_hash(NETWORK_PASSPHRASE_PUBNET, 2, b"body");
        let h2 = compute_stellar_hash(NETWORK_PASSPHRASE_PUBNET, 2, b"body");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_stellar_hash_different_envelope_types() {
        let h_tx = compute_stellar_hash(NETWORK_PASSPHRASE_PUBNET, 2, b"body");
        let h_auth = compute_stellar_hash(
            NETWORK_PASSPHRASE_PUBNET,
            ENVELOPE_TYPE_SOROBAN_AUTHORIZATION,
            b"body",
        );
        assert_ne!(
            h_tx, h_auth,
            "different envelope types produce different hashes"
        );
    }

    #[test]
    fn test_compute_stellar_hash_different_networks() {
        let h_pub = compute_stellar_hash(NETWORK_PASSPHRASE_PUBNET, 2, b"body");
        let h_test = compute_stellar_hash(NETWORK_PASSPHRASE_TESTNET, 2, b"body");
        assert_ne!(h_pub, h_test, "different networks produce different hashes");
    }

    #[test]
    fn test_compute_stellar_hash_matches_precomputed_id() {
        // compute_stellar_hash should produce the same result as using
        // the pre-computed PUBNET_NETWORK_ID constant directly
        let body = b"test_body";
        let via_helper = compute_stellar_hash(NETWORK_PASSPHRASE_PUBNET, 2, body);

        let mut manual_preimage = Vec::new();
        manual_preimage.extend_from_slice(&PUBNET_NETWORK_ID);
        manual_preimage.extend_from_slice(&2u32.to_be_bytes());
        manual_preimage.extend_from_slice(body);
        let via_manual: [u8; 32] = Sha256::digest(&manual_preimage).into();

        assert_eq!(via_helper, via_manual);
    }

    // ---------------------------------------------------------------
    // Soroban auth entry signing
    // ---------------------------------------------------------------

    #[test]
    fn test_sign_auth_entry() {
        let privkey = test_privkey();
        let auth_entry = b"fake_soroban_auth_entry_xdr";

        let result = StellarSigner.sign_auth_entry(&privkey, auth_entry).unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.public_key.is_some());

        // Verify the signature is over compute_stellar_hash with envelope type 29
        let digest = compute_stellar_hash(
            NETWORK_PASSPHRASE_PUBNET,
            ENVELOPE_TYPE_SOROBAN_AUTHORIZATION,
            auth_entry,
        );
        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key
            .verify(&digest, &sig)
            .expect("Soroban auth signature should verify");
    }

    #[test]
    fn test_sign_soroban_auth_differs_from_tx() {
        let privkey = test_privkey();
        let body = b"same_body";

        let tx_result = StellarSigner.sign_transaction(&privkey, body).unwrap();
        let auth_result = StellarSigner.sign_auth_entry(&privkey, body).unwrap();

        assert_ne!(
            tx_result.signature, auth_result.signature,
            "tx and auth signatures differ due to different envelope types"
        );
    }

    #[test]
    fn test_sign_auth_entry_invalid_key() {
        let bad_key = vec![0u8; 16];
        assert!(StellarSigner.sign_auth_entry(&bad_key, b"auth").is_err());
    }
}
