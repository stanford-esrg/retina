// crypto.rs contains the cryptograpic functions needed to derive QUIC
// initial keys. These keys can be used to remove header protection and
// decrypt QUIC initial packets. This file is heavily based on Cloudflare's
// crypto module in their Rust implementation of QUIC, known as Quiche.
// Therefore, the original license from https://github.com/cloudflare/quiche/blob/master/quiche/src/crypto/mod.rs is below:

// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::iter::repeat;

use crypto::aead::AeadDecryptor;
use crypto::aes::KeySize;
use crypto::aes_gcm::AesGcm;
use ring::aead;
use ring::hkdf;

use crate::protocols::stream::quic::parser::QuicVersion;
use crate::protocols::stream::quic::QuicError;

// The algorithm enum defines the available
// cryptographic algorithms used to secure
// QUIC packets.
#[derive(Copy, Clone, Debug)]
pub enum Algorithm {
    AES128GCM,
}

impl Algorithm {
    fn get_ring_hp(self) -> &'static aead::quic::Algorithm {
        match self {
            Algorithm::AES128GCM => &aead::quic::AES_128,
        }
    }

    fn get_ring_digest(self) -> hkdf::Algorithm {
        match self {
            Algorithm::AES128GCM => hkdf::HKDF_SHA256,
        }
    }

    pub fn key_len(self) -> usize {
        match self {
            Algorithm::AES128GCM => 16,
        }
    }

    pub fn tag_len(self) -> usize {
        match self {
            Algorithm::AES128GCM => 16,
        }
    }

    pub fn nonce_len(self) -> usize {
        match self {
            Algorithm::AES128GCM => 12,
        }
    }

    pub fn get_key_len(self) -> Option<KeySize> {
        match self {
            Algorithm::AES128GCM => Some(KeySize::KeySize128),
        }
    }
}

// The Open struct gives a return value
// that contains all of the components
// needed for HP removal and decryption
pub struct Open {
    alg: Algorithm,

    key_len: Option<KeySize>,

    initial_key: Vec<u8>,

    hp_key: aead::quic::HeaderProtectionKey,

    iv: Vec<u8>,
}

impl Open {
    pub fn new(alg: Algorithm, key: &[u8], iv: &[u8], hp_key: &[u8]) -> Result<Open, QuicError> {
        Ok(Open {
            alg,

            key_len: alg.get_key_len(),

            initial_key: key.to_vec(),

            hp_key: aead::quic::HeaderProtectionKey::new(alg.get_ring_hp(), hp_key)
                .map_err(|_| QuicError::CryptoFail)?,

            iv: iv.to_vec(),
        })
    }

    pub fn open_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, QuicError> {
        let nonce = make_nonce(&self.iv, counter);
        let mut cipher = match self.alg {
            Algorithm::AES128GCM => {
                AesGcm::new(self.key_len.unwrap(), &self.initial_key, &nonce, ad)
            }
        };

        let mut out: Vec<u8> = repeat(0).take(buf.len()).collect();

        let rc = cipher.decrypt(buf, &mut out, tag);

        if !rc {
            return Err(QuicError::CryptoFail);
        }

        Ok(out)
    }

    pub fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5], QuicError> {
        let mask = self
            .hp_key
            .new_mask(sample)
            .map_err(|_| QuicError::CryptoFail)?;

        Ok(mask)
    }

    pub fn alg(&self) -> Algorithm {
        self.alg
    }

    pub fn sample_len(&self) -> usize {
        self.hp_key.algorithm().sample_len()
    }
}
impl std::fmt::Debug for Open {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Point")
            .field("alg", &self.alg)
            .field("iv", &self.iv)
            .finish()
    }
}

pub fn calc_init_keys(cid: &[u8], version: u32) -> Result<[Open; 2], QuicError> {
    let aead = Algorithm::AES128GCM;
    let key_len = aead.key_len();
    let nonce_len = aead.nonce_len();
    let initial_secret = derive_initial_secret(cid, version);

    let mut secret = [0; 32];
    let mut client_key = vec![0; key_len];
    let mut client_iv = vec![0; nonce_len];
    let mut client_hp_key = vec![0; key_len];

    derive_client_initial_secret(&initial_secret, &mut secret)?;
    derive_pkt_key(aead, &secret, &mut client_key)?;
    derive_pkt_iv(aead, &secret, &mut client_iv)?;
    derive_hdr_key(aead, &secret, &mut client_hp_key)?;

    // Server.
    let mut server_key = vec![0; key_len];
    let mut server_iv = vec![0; nonce_len];
    let mut server_hp_key = vec![0; key_len];

    derive_server_initial_secret(&initial_secret, &mut secret)?;
    derive_pkt_key(aead, &secret, &mut server_key)?;
    derive_pkt_iv(aead, &secret, &mut server_iv)?;
    derive_hdr_key(aead, &secret, &mut server_hp_key)?;

    Ok([
        Open::new(aead, &client_key, &client_iv, &client_hp_key)?,
        Open::new(aead, &server_key, &server_iv, &server_hp_key)?,
    ])
}

fn derive_initial_secret(secret: &[u8], version: u32) -> hkdf::Prk {
    const INITIAL_SALT_RFC9000: [u8; 20] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];

    const INITIAL_SALT_RFC9369: [u8; 20] = [
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d,
        0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
    ];

    const INITIAL_SALT_DRAFT29: [u8; 20] = [
        0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11,
        0xe0, 0x43, 0x90, 0xa8, 0x99,
    ];

    const INITIAL_SALT_DRAFT27: [u8; 20] = [
        0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4, 0x63,
        0x65, 0xbe, 0xf9, 0xf5, 0x02,
    ];

    let salt = match QuicVersion::from_u32(version) {
        QuicVersion::Rfc9000 => &INITIAL_SALT_RFC9000,
        QuicVersion::Rfc9369 => &INITIAL_SALT_RFC9369,
        QuicVersion::Draft29 => &INITIAL_SALT_DRAFT29,
        QuicVersion::Draft27 | QuicVersion::Draft28 | QuicVersion::Mvfst27 => &INITIAL_SALT_DRAFT27,
        _ => &INITIAL_SALT_RFC9000,
    };

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    salt.extract(secret)
}

fn derive_client_initial_secret(prk: &hkdf::Prk, out: &mut [u8]) -> Result<(), QuicError> {
    const LABEL: &[u8] = b"client in";
    hkdf_expand_label(prk, LABEL, out)
}

fn derive_server_initial_secret(prk: &hkdf::Prk, out: &mut [u8]) -> Result<(), QuicError> {
    const LABEL: &[u8] = b"server in";
    hkdf_expand_label(prk, LABEL, out)
}

pub fn derive_hdr_key(aead: Algorithm, secret: &[u8], out: &mut [u8]) -> Result<(), QuicError> {
    const LABEL: &[u8] = b"quic hp";

    let key_len = aead.key_len();

    if key_len > out.len() {
        return Err(QuicError::CryptoFail);
    }

    let secret = hkdf::Prk::new_less_safe(aead.get_ring_digest(), secret);
    hkdf_expand_label(&secret, LABEL, &mut out[..key_len])
}

pub fn derive_pkt_key(aead: Algorithm, secret: &[u8], out: &mut [u8]) -> Result<(), QuicError> {
    const LABEL: &[u8] = b"quic key";

    let key_len = aead.key_len();

    if key_len > out.len() {
        return Err(QuicError::CryptoFail);
    }

    let secret = hkdf::Prk::new_less_safe(aead.get_ring_digest(), secret);
    hkdf_expand_label(&secret, LABEL, &mut out[..key_len])
}

pub fn derive_pkt_iv(aead: Algorithm, secret: &[u8], out: &mut [u8]) -> Result<(), QuicError> {
    const LABEL: &[u8] = b"quic iv";

    let nonce_len = aead.nonce_len();

    if nonce_len > out.len() {
        return Err(QuicError::CryptoFail);
    }

    let secret = hkdf::Prk::new_less_safe(aead.get_ring_digest(), secret);
    hkdf_expand_label(&secret, LABEL, &mut out[..nonce_len])
}

fn hkdf_expand_label(prk: &hkdf::Prk, label: &[u8], out: &mut [u8]) -> Result<(), QuicError> {
    const LABEL_PREFIX: &[u8] = b"tls13 ";

    let out_len = (out.len() as u16).to_be_bytes();
    let label_len = (LABEL_PREFIX.len() + label.len()) as u8;

    let info = [&out_len, &[label_len][..], LABEL_PREFIX, label, &[0][..]];

    prk.expand(&info, ArbitraryOutputLen(out.len()))
        .map_err(|_| QuicError::CryptoFail)?
        .fill(out)
        .map_err(|_| QuicError::CryptoFail)?;

    Ok(())
}

fn make_nonce(iv: &[u8], counter: u64) -> [u8; aead::NONCE_LEN] {
    let mut nonce = [0; aead::NONCE_LEN];
    nonce.copy_from_slice(iv);

    // XOR the last bytes of the IV with the counter. This is equivalent to
    // left-padding the counter with zero bytes.
    for (a, b) in nonce[4..].iter_mut().zip(counter.to_be_bytes().iter()) {
        *a ^= b;
    }

    nonce
}

// The ring HKDF expand() API does not accept an arbitrary output length, so we
// need to hide the `usize` length as part of a type that implements the trait
// `ring::hkdf::KeyType` in order to trick ring into accepting it.
struct ArbitraryOutputLen(usize);

impl hkdf::KeyType for ArbitraryOutputLen {
    fn len(&self) -> usize {
        self.0
    }
}
