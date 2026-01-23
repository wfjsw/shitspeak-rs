use aws_lc_rs::{cipher::{AES_128, DecryptingKey, EncryptingKey, UnboundCipherKey}, rand::{self, SecureRandom}};

use crate::client::crypt::{errors::CryptError, CryptoMode};

const BLOCK_SIZE: usize = 16;

pub struct Ocb2 {
    encrypt_key: EncryptingKey,
    decrypt_key: DecryptingKey,
}

impl Ocb2 {
    pub fn from_key(key: [u8; BLOCK_SIZE]) -> Result<Self, CryptError> {
        Ok(Ocb2 {
            encrypt_key: EncryptingKey::ecb(UnboundCipherKey::new(&AES_128, &key)?)?,
            decrypt_key: DecryptingKey::ecb(UnboundCipherKey::new(&AES_128, &key)?)?,
        })
    }

    pub fn new(rng: &dyn SecureRandom) -> Result<Self, CryptError> {
        let mut key = [0u8; BLOCK_SIZE];
        rng.fill(&mut key)?;
        Ocb2::from_key(key)
    }
}

impl CryptoMode for Ocb2 {
    fn nonce_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn key_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn overhead(&self) -> usize {
        3
    }

    fn encrypt(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, CryptError> {
        if nonce.len() != self.nonce_size() {
            return Err(CryptError::InvalidNonceSize);
        }

        // output buffer
        let mut out = Vec::<u8>::with_capacity(data.len() + self.overhead());

        // delta = E(nonce)
        let mut delta = [0u8; BLOCK_SIZE];
        delta.copy_from_slice(nonce);
        self.encrypt_key.encrypt(&mut delta)?;

        let mut checksum = [0u8; BLOCK_SIZE];

        let mut tmp = [0u8; BLOCK_SIZE];
        let mut pad = [0u8; BLOCK_SIZE];
        let mut tag_block = [0u8; BLOCK_SIZE];

        let mut pos = 0usize;
        let mut remaining = data.len();

        // Process all full blocks except the final block
        while remaining > BLOCK_SIZE {
            times2(&mut delta);

            tmp.copy_from_slice(&data[pos..pos + BLOCK_SIZE]);
            xor(&mut tmp, &delta);

            self.encrypt_key.encrypt(&mut tmp)?;

            let mut out_block = [0u8; BLOCK_SIZE];
            xor_into(&mut out_block, &delta, &tmp);
            out.extend_from_slice(&out_block);

            xor(&mut checksum, &data[pos..pos + BLOCK_SIZE]);

            pos += BLOCK_SIZE;
            remaining -= BLOCK_SIZE;
        }

        // Final (partial or zero-length) block
        times2(&mut delta);
        tmp.fill(0);
        let num_bits = (remaining * 8) as u16;
        tmp[BLOCK_SIZE - 2] = ((num_bits >> 8) & 0xff) as u8;
        tmp[BLOCK_SIZE - 1] = (num_bits & 0xff) as u8;
        xor(&mut tmp, &delta);

        pad.copy_from_slice(&tmp);
        self.encrypt_key.encrypt(&mut pad)?;

        if remaining > 0 {
            tmp[..remaining].copy_from_slice(&data[pos..pos + remaining]);
        }
        tmp[remaining..].copy_from_slice(&pad[remaining..]);

        xor(&mut checksum, &tmp);

        // ciphertext fragment: pad XOR tmp (only `remaining` bytes)
        for i in 0..remaining {
            out.push(pad[i] ^ tmp[i]);
        }

        // finalize tag: tag = E((3*delta) xor checksum)
        let mut delta2 = delta;
        times2(&mut delta2);
        for i in 0..BLOCK_SIZE {
            tag_block[i] = delta[i] ^ delta2[i] ^ checksum[i];
        }
        self.encrypt_key.encrypt(&mut tag_block)?;

        out.extend_from_slice(&tag_block[..self.overhead()]);
        Ok(out)
    }

    fn decrypt(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, CryptError> {
        if nonce.len() != self.nonce_size() {
            return Err(CryptError::InvalidNonceSize);
        }

        if data.len() < self.overhead() {
            return Err(CryptError::DataTooShort);
        }

        let tag_len = self.overhead();
        let ct_len = data.len() - tag_len;

        let mut plain = vec![0u8; ct_len];

        // prepare
        let mut checksum = [0u8; BLOCK_SIZE];
        let mut delta = [0u8; BLOCK_SIZE];
        delta.copy_from_slice(nonce);
        self.encrypt_key.encrypt(&mut delta)?;

        let mut tmp = [0u8; BLOCK_SIZE];
        let mut pad = [0u8; BLOCK_SIZE];
        let mut calc_tag = [0u8; BLOCK_SIZE];

        let mut off = 0usize;
        let mut remain = ct_len;

        // process full blocks
        while remain > BLOCK_SIZE {
            times2(&mut delta);

            // tmp = delta xor ciphertext_block
            xor_into(&mut tmp, &delta, &data[off..off + BLOCK_SIZE]);

            // decrypt tmp in-place
            self.decrypt_key
                .decrypt(&mut tmp, aws_lc_rs::cipher::DecryptionContext::None)?;

            // plain_block = delta xor tmp
            let mut out_block = [0u8; BLOCK_SIZE];
            xor_into(&mut out_block, &delta, &tmp);
            plain[off..off + BLOCK_SIZE].copy_from_slice(&out_block);

            // checksum ^= plain_block
            xor(&mut checksum, &plain[off..off + BLOCK_SIZE]);

            off += BLOCK_SIZE;
            remain -= BLOCK_SIZE;
        }

        // final partial block
        times2(&mut delta);
        tmp.fill(0);
        let num_bits = (remain * 8) as u16;
        tmp[BLOCK_SIZE - 2] = ((num_bits >> 8) & 0xff) as u8;
        tmp[BLOCK_SIZE - 1] = (num_bits & 0xff) as u8;
        xor(&mut tmp, &delta);

        pad.copy_from_slice(&tmp);
        self.encrypt_key.encrypt(&mut pad)?;

        // tmp = ciphertext fragment (in first `remain` bytes)
        tmp.fill(0);
        let _ = (&mut tmp[..remain]).copy_from_slice(&data[off..off + remain]);

        // tmp = tmp xor pad
        xor(&mut tmp, &pad);

        // checksum ^= tmp
        xor(&mut checksum, &tmp);

        // write plaintext fragment
        plain[off..off + remain].copy_from_slice(&tmp[..remain]);

        // finalize tag: E((3*delta) xor checksum)
        let mut delta2 = delta;
        times2(&mut delta2);
        for i in 0..BLOCK_SIZE {
            calc_tag[i] = delta[i] ^ delta2[i] ^ checksum[i];
        }
        self.encrypt_key.encrypt(&mut calc_tag)?;

        // constant-time compare of computed tag prefix with provided tag
        let provided_tag = &data[ct_len..];
        if !consttime_eq(&calc_tag[..tag_len], provided_tag) {
            return Err(CryptError::TagMismatch);
        }

        Ok(plain)
    }
}

fn consttime_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn xor(d: &mut [u8], s: &[u8]) {
    d.iter_mut().zip(s.iter()).for_each(|(d, &s)| *d = *d ^ s);
}

fn xor_into(dst: &mut [u8], a: &[u8], b: &[u8]) {
    dst.iter_mut()
        .zip(a.iter())
        .zip(b.iter())
        .for_each(|((d, &a), &b)| *d = a ^ b);
}

// times2 performs the times2 operation, defined as:
//
// times2(S)
//     S << 1 if S[1] = 0, and (S << 1) xor const(bitlength(S)) if S[1] = 1.
//
// where const(n) is defined as
//
// const(n)
//     The lexicographically first n-bit string C among all
//     strings that have a minimal possible number of "1"
//     bits and which name a polynomial x^n + C[1] *
//     x^{n-1} + ... + C[n-1] * x^1 + C[n] * x^0 that is
//     irreducible over the field with two elements.  In
//     particular, const(128) = num2str(135, 128).  For
//     other values of n, refer to a standard table of
//     irreducible polynomials [G. Seroussi,
//     "Table of low-weight binary irreducible polynomials",
//     HP Labs Technical Report HPL-98-135, 1998.].
//
// and num2str(x, n) is defined as
//
// num2str(x, n)
//     The n-bit binary representation of the integer x.
//     More formally, the n-bit string S where x = S[1] *
//     2^{n-1} + S[2] * 2^{n-2} + ... + S[n] * 2^{0}.  Only
//     used when 0 <= x < 2^n.
//
// For our 128-bit block size implementation, this means that
// the xor with const(bitlength(S)) if S[1] = 1 is implemented
// by simply xor'ing the last byte with the number 135 when
// S[1] = 1.
fn times2(d: &mut [u8]) {
    assert!(d.len() == BLOCK_SIZE);
    let carry = (d[0] >> 7) & 0x1;
    for i in 0..(BLOCK_SIZE - 1) {
        d[i] = (d[i] << 1) | ((d[i + 1] >> 7) & 0x1);
    }
    d[BLOCK_SIZE - 1] = (d[BLOCK_SIZE - 1] << 1) ^ (carry * 0x87);
}

// times3 performs the times3 operation, defined as:
//
// times3(S)
//     times2(S) xor S
fn times3(d: &mut [u8]) {
    assert!(d.len() == BLOCK_SIZE);
    let carry = (d[0] >> 7) & 0x1;
    for i in 0..(BLOCK_SIZE - 1) {
        d[i] ^= (d[i] << 1) | ((d[i + 1] >> 7) & 0x1);
    }
    d[BLOCK_SIZE - 1] ^= (d[BLOCK_SIZE - 1] << 1) ^ (carry * 0x87);
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::decode;

    fn must_decode_hex(s: &str) -> Vec<u8> {
        decode(s).expect("invalid hex")
    }

    struct OcbVector {
        _name: &'static str,
        key: &'static str,
        nonce: &'static str,
        plaintext: &'static str,
        ciphertext: &'static str,
        tag: &'static str,
    }

    const VECTORS: &[OcbVector] = &[
        OcbVector {
            _name: "OCB2-AES-128-001",
            key: "000102030405060708090A0B0C0D0E0F",
            nonce: "000102030405060708090A0B0C0D0E0F",
            plaintext: "",
            ciphertext: "",
            tag: "BF3108130773AD5EC70EC69E7875A7B0",
        },
        OcbVector {
            _name: "OCB2-AES-128-002",
            key: "000102030405060708090A0B0C0D0E0F",
            nonce: "000102030405060708090A0B0C0D0E0F",
            plaintext: "0001020304050607",
            ciphertext: "C636B3A868F429BB",
            tag: "A45F5FDEA5C088D1D7C8BE37CABC8C5C",
        },
        OcbVector {
            _name: "OCB2-AES-128-003",
            key: "000102030405060708090A0B0C0D0E0F",
            nonce: "000102030405060708090A0B0C0D0E0F",
            plaintext: "000102030405060708090A0B0C0D0E0F",
            ciphertext: "52E48F5D19FE2D9869F0C4A4B3D2BE57",
            tag: "F7EE49AE7AA5B5E6645DB6B3966136F9",
        },
        OcbVector {
            _name: "OCB2-AES-128-003b",
            key: "000102030405060708090A0B0C0D0E0F",
            nonce: "000102030405060708090A0B0C0D0E0F",
            plaintext: "000102030405060708090A0B0C0D0E0F1011121314151617",
            ciphertext: "F75D6BC8B4DC8D66B836A2B08B32A636CC579E145D323BEB",
            tag: "A1A50F822819D6E0A216784AC24AC84C",
        },
        OcbVector {
            _name: "OCB2-AES-128-004",
            key: "000102030405060708090A0B0C0D0E0F",
            nonce: "000102030405060708090A0B0C0D0E0F",
            plaintext: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            ciphertext: "F75D6BC8B4DC8D66B836A2B08B32A636CEC3C555037571709DA25E1BB0421A27",
            tag: "09CA6C73F0B5C6C5FD587122D75F2AA3",
        },
        OcbVector {
            _name: "OCB2-AES-128-005",
            key: "000102030405060708090A0B0C0D0E0F",
            nonce: "000102030405060708090A0B0C0D0E0F",
            plaintext:
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
            ciphertext:
                "F75D6BC8B4DC8D66B836A2B08B32A6369F1CD3C5228D79FD6C267F5F6AA7B231C7DFB9D59951AE9C",
            tag: "9DB0CDF880F73E3E10D4EB3217766688",
        },
    ];

    #[test]
    fn test_times2_and_times3_and_xor() {
        let mut msg: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
        msg[0] = 0x80;
        for i in 1..(BLOCK_SIZE - 1) {
            msg[i] = 0xff;
        }
        msg[BLOCK_SIZE - 1] = 0xfe;

        let mut expect2 = [0u8; BLOCK_SIZE];
        expect2[0] = 0x01;
        for i in 1..(BLOCK_SIZE - 1) {
            expect2[i] = 0xff;
        }
        expect2[BLOCK_SIZE - 1] = 0x7b;

        let mut m2 = msg;
        times2(&mut m2);
        assert_eq!(m2, expect2);

        let mut m3 = msg;
        times3(&mut m3);
        let mut expect3 = [0u8; BLOCK_SIZE];
        expect3[0] = 0x81;
        expect3[BLOCK_SIZE - 1] = 0x85;
        assert_eq!(m3, expect3);

        // xor test
        let mut out = [0u8; BLOCK_SIZE];
        xor(&mut out, &msg);
        // out should be msg xor msg == zero
        let mut tmp = [0u8; BLOCK_SIZE];
        xor(&mut tmp, &out);
        assert_eq!(tmp, msg);
    }

    #[test]
    fn test_encrypt_decrypt_vectors() {
        for v in VECTORS {
            let key_bytes = must_decode_hex(v.key);
            let key_arr: [u8; BLOCK_SIZE] = key_bytes.as_slice().try_into().unwrap();
            let ocb = Ocb2::from_key(key_arr).unwrap();

            let nonce = must_decode_hex(v.nonce);
            let plain = must_decode_hex(v.plaintext);
            let expected_ct = must_decode_hex(v.ciphertext);
            let expected_tag = must_decode_hex(v.tag);

            let out = ocb.encrypt(&plain, &nonce).expect("encrypt failed");

            // split ciphertext and tag
            let ct = &out[..plain.len()];
            let tag = &out[plain.len()..];

            assert_eq!(
                ct,
                expected_ct.as_slice(),
                "ciphertext mismatch for {}",
                v._name
            );

            // expected_tag is 16 bytes; compare prefix of length overhead()
            assert_eq!(
                tag,
                &expected_tag[..ocb.overhead()],
                "tag mismatch for {}",
                v._name
            );

            // decrypt
            let mut combined = Vec::with_capacity(out.len());
            combined.extend_from_slice(ct);
            combined.extend_from_slice(tag);

            let dec = ocb.decrypt(&combined, &nonce).expect("decrypt failed");
            assert_eq!(dec, plain, "decrypted plaintext mismatch for {}", v._name);
        }
    }
}
