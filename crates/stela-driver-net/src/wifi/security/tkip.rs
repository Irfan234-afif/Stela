// SPDX-License-Identifier: GPL-2.0-only
// TKIP adapted from Linux net/mac80211/tkip.c and net/mac80211/wep.c; source
// notices in NOTICE.
//! TKIP decryption in software, as mac80211 runs it for a key the driver's
//! `set_key` refused: rtw89 refuses TKIP on a chip whose `hw_tkip_crypto` is
//! false, the RTL8852B among them, so its station decrypts a TKIP group
//! key's frames here, then checks their Michael with [`super::michael`] as it
//! does for a chip that decrypted them.

use super::wep::rc4;
// The ICV is WEP's, `~crc32_le(~0, bytes)`, the IEEE CRC-32.
use stela_driver_core::crc::crc32_ieee as crc32;
use zeroize::Zeroize;

/// `IEEE80211_TKIP_IV_LEN` and `IEEE80211_TKIP_ICV_LEN`.
pub const IV_BYTES: usize = 8;
pub const ICV_BYTES: usize = 4;
/// `PHASE1_LOOP_COUNT`.
const PHASE1_LOOP_COUNT: u16 = 8;

/// GF(2^8) doubling under AES's polynomial.
const fn double(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 }
}

/// The AES S-box's entry for `x`: its inverse in GF(2^8), 0 for 0, through
/// the affine map.
const fn aes_sbox(x: u8) -> u8 {
    // x^254 by square and multiply.
    let (mut inverse, mut base, mut exponent) = (1u8, x, 254u8);
    while exponent != 0 {
        if exponent & 1 != 0 {
            inverse = multiply(inverse, base);
        }
        base = multiply(base, base);
        exponent >>= 1;
    }
    let b = if x == 0 { 0 } else { inverse };
    b ^ b.rotate_left(1) ^ b.rotate_left(2) ^ b.rotate_left(3) ^ b.rotate_left(4) ^ 0x63
}

const fn multiply(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        a = double(a);
        b >>= 1;
    }
    product
}

/// `tkip_sbox`: each AES S-box entry s as the two bytes 2s and 3s, the
/// half of the table `tkipS` swaps for its high byte.
const SBOX: [u16; 256] = {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        let s = aes_sbox(i as u8);
        table[i] = (double(s) as u16) << 8 | (double(s) ^ s) as u16;
        i += 1;
    }
    table
};

/// `tkipS`.
fn s(value: u16) -> u16 {
    SBOX[usize::from(value as u8)] ^ SBOX[usize::from(value >> 8)].swap_bytes()
}

/// The little-endian word of `tk` at `at`.
fn word(tk: &[u8; 16], at: usize) -> u16 {
    u16::from_le_bytes([tk[at], tk[at + 1]])
}

/// `tkip_mixing_phase1`: the P1K of temporal key `tk`, transmitter `ta` and
/// the TSC's high 32 bits, `iv32`.
pub fn phase1(tk: &[u8; 16], ta: &[u8; 6], iv32: u32) -> [u16; 5] {
    let mut p1k = [
        iv32 as u16,
        (iv32 >> 16) as u16,
        u16::from_le_bytes([ta[0], ta[1]]),
        u16::from_le_bytes([ta[2], ta[3]]),
        u16::from_le_bytes([ta[4], ta[5]]),
    ];
    for i in 0..PHASE1_LOOP_COUNT {
        let j = 2 * usize::from(i & 1);
        p1k[0] = p1k[0].wrapping_add(s(p1k[4] ^ word(tk, j)));
        p1k[1] = p1k[1].wrapping_add(s(p1k[0] ^ word(tk, 4 + j)));
        p1k[2] = p1k[2].wrapping_add(s(p1k[1] ^ word(tk, 8 + j)));
        p1k[3] = p1k[3].wrapping_add(s(p1k[2] ^ word(tk, 12 + j)));
        p1k[4] = p1k[4].wrapping_add(s(p1k[3] ^ word(tk, j))).wrapping_add(i);
    }
    p1k
}

/// `tkip_mixing_phase2`: the RC4 key of `tk` and `p1k` for the TSC's low 16
/// bits, `iv16`, its first three bytes `write_tkip_iv`'s.
pub fn phase2(tk: &[u8; 16], p1k: &[u16; 5], iv16: u16) -> [u8; 16] {
    let mut ppk = [p1k[0], p1k[1], p1k[2], p1k[3], p1k[4], 0];
    ppk[5] = p1k[4].wrapping_add(iv16);
    for i in 0..6 {
        let previous = ppk[(i + 5) % 6];
        ppk[i] = ppk[i].wrapping_add(s(previous ^ word(tk, 2 * i)));
    }
    ppk[0] = ppk[0].wrapping_add((ppk[5] ^ word(tk, 12)).rotate_right(1));
    ppk[1] = ppk[1].wrapping_add((ppk[0] ^ word(tk, 14)).rotate_right(1));
    for i in 2..6 {
        ppk[i] = ppk[i].wrapping_add(ppk[i - 1].rotate_right(1));
    }
    let [high, low] = iv16.to_be_bytes();
    let mut key = [0; 16];
    key[0] = high;
    key[1] = (high | 0x20) & 0x7f;
    key[2] = low;
    key[3] = ((ppk[5] ^ word(tk, 0)) >> 1) as u8;
    for (bytes, value) in key[4..].as_chunks_mut::<2>().0.iter_mut().zip(ppk) {
        *bytes = value.to_le_bytes();
    }
    ppk.zeroize();
    key
}

/// Why `ieee80211_tkip_decrypt_data` refused a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// Shorter than its IV and ICV.
    Short,
    /// `TKIP_DECRYPT_NO_EXT_IV`.
    NoExtendedIv,
    /// The ICV failed, `ieee80211_wep_decrypt_data`'s mismatch.
    Icv,
}

/// `ieee80211_tkip_decrypt_data` past its key index and replay checks, which
/// the caller's key lookup and key slot make: `body`, an MPDU's bytes past
/// its MAC header, decrypted in place under temporal key `tk` of transmitter
/// `ta`, the IV and ICV left where they were, as mac80211 strips them only
/// once this returns.
pub fn decrypt(tk: &[u8; 16], ta: &[u8; 6], body: &mut [u8]) -> Result<(), Failure> {
    if body.len() < IV_BYTES + ICV_BYTES {
        return Err(Failure::Short);
    }
    if body[3] & 0x20 == 0 {
        return Err(Failure::NoExtendedIv);
    }
    let iv16 = u16::from_be_bytes([body[0], body[2]]);
    let iv32 = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
    let mut p1k = phase1(tk, ta, iv32);
    let mut key = phase2(tk, &p1k, iv16);
    p1k.zeroize();
    let sealed = &mut body[IV_BYTES..];
    rc4(&key, sealed);
    key.zeroize();
    let (plain, icv) = sealed.split_at(sealed.len() - ICV_BYTES);
    if crc32(plain).to_le_bytes() != icv {
        return Err(Failure::Icv);
    }
    Ok(())
}

/// `ieee80211_tkip_add_iv` and `ieee80211_tkip_encrypt_data`: `plain` sealed
/// under `tk` by `ta` at TSC `tsc` with key `index`, its IV first and its ICV
/// last, as an AP sends a TKIP frame's body.
#[cfg(test)]
pub(crate) fn encrypt(
    tk: &[u8; 16],
    ta: &[u8; 6],
    tsc: u64,
    index: u8,
    plain: &[u8],
) -> alloc::vec::Vec<u8> {
    let (iv16, iv32) = (tsc as u16, (tsc >> 16) as u32);
    let key = phase2(tk, &phase1(tk, ta, iv32), iv16);
    let mut body = alloc::vec![key[0], key[1], key[2], index << 6 | 0x20];
    body.extend_from_slice(&iv32.to_le_bytes());
    let start = body.len();
    body.extend_from_slice(plain);
    body.extend_from_slice(&crc32(plain).to_le_bytes());
    rc4(&key, &mut body[start..]);
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sbox_is_tkip_c_s_table() {
        assert_eq!(
            SBOX[..8],
            [
                0xc6a5, 0xf884, 0xee99, 0xf68d, 0xff0d, 0xd6bd, 0xdeb1, 0x9154
            ]
        );
        assert_eq!(SBOX[0x52], 0x0000);
        assert_eq!(
            SBOX[248..],
            [
                0x82c3, 0x29b0, 0x5a77, 0x1e11, 0x7bcb, 0xa8fc, 0x6dd6, 0x2c3a
            ]
        );
    }

    /// The TKIP key mixing test vectors of IEEE 802.11i's reference code:
    /// a TSC's P1K and RC4 key.
    #[test]
    fn key_mixing_gives_the_standards_vectors() {
        let tk1: [u8; 16] = core::array::from_fn(|i| i as u8);
        let ta1 = [0x10, 0x22, 0x33, 0x44, 0x55, 0x66];
        let tk2 = [
            0x63, 0x89, 0x3b, 0x25, 0x08, 0x40, 0xb8, 0xae, 0x0b, 0xd0, 0xfa, 0x7e, 0x61, 0xd2,
            0x78, 0x3e,
        ];
        let ta2 = [0x64, 0xf2, 0xea, 0xed, 0xdc, 0x25];
        /// TK, TA, IV32, IV16, P1K and the RC4 key.
        type Vector<'a> = (&'a [u8; 16], &'a [u8; 6], u32, u16, [u16; 5], [u8; 16]);
        let vectors: [Vector<'_>; 4] = [
            (
                &tk1,
                &ta1,
                0,
                0,
                [0x3dd2, 0x016e, 0x76f4, 0x8697, 0xb2e8],
                [
                    0x00, 0x20, 0x00, 0x33, 0xea, 0x8d, 0x2f, 0x60, 0xca, 0x6d, 0x13, 0x74, 0x23,
                    0x4a, 0x66, 0x0b,
                ],
            ),
            (
                &tk1,
                &ta1,
                0,
                1,
                [0x3dd2, 0x016e, 0x76f4, 0x8697, 0xb2e8],
                [
                    0x00, 0x20, 0x01, 0x90, 0xff, 0xdc, 0x31, 0x43, 0x89, 0xa9, 0xd9, 0xd0, 0x74,
                    0xfd, 0x20, 0xaa,
                ],
            ),
            (
                &tk2,
                &ta2,
                0x20dc_fd43,
                0xffff,
                [0x7c67, 0x49d7, 0x9724, 0xb5e9, 0xb4f1],
                [
                    0xff, 0x7f, 0xff, 0x93, 0x81, 0x0f, 0xc6, 0xe5, 0x8f, 0x5d, 0xd3, 0x26, 0x25,
                    0x15, 0x44, 0xce,
                ],
            ),
            (
                &tk2,
                &ta2,
                0x20dc_fd44,
                0,
                [0x5a5d, 0x73a8, 0xa859, 0x2ec1, 0xdc8b],
                [
                    0x00, 0x20, 0x00, 0x49, 0x8c, 0xa4, 0x71, 0xfc, 0xfb, 0xfa, 0xa1, 0x6e, 0x36,
                    0x10, 0xf0, 0x05,
                ],
            ),
        ];
        for (n, (tk, ta, iv32, iv16, p1k, key)) in vectors.into_iter().enumerate() {
            assert_eq!(phase1(tk, ta, iv32), p1k, "vector {}", n + 1);
            assert_eq!(phase2(tk, &p1k, iv16), key, "vector {}", n + 1);
        }
    }

    #[test]
    fn a_sealed_body_opens_in_place_with_its_iv_and_icv_kept() {
        let tk = [0x5a; 16];
        let ta = [2, 0xd2, 0x0b, 0x10, 0x20, 0x30];
        let plain = b"\xaa\xaa\x03\x00\x00\x00\x08\x00datagram and its michael";
        let tsc = 0x0001_2345_ffff;
        let sealed = encrypt(&tk, &ta, tsc, 1, plain);
        // The IV names TSC1, its WEP seed, TSC0, key 1 with Extended IV,
        // then IV32.
        assert_eq!(
            sealed[..8],
            [0xff, 0x7f, 0xff, 0x60, 0x45, 0x23, 0x01, 0x00]
        );
        let mut body = sealed.clone();
        decrypt(&tk, &ta, &mut body).unwrap();
        assert_eq!(body[..8], sealed[..8]);
        assert_eq!(&body[8..body.len() - ICV_BYTES], plain);
        // One bit off anywhere sealed, under another key or from another
        // transmitter, the ICV fails.
        let mut flipped = sealed.clone();
        flipped[20] ^= 1;
        assert_eq!(decrypt(&tk, &ta, &mut flipped), Err(Failure::Icv));
        assert_eq!(
            decrypt(&[0x5b; 16], &ta, &mut sealed.clone()),
            Err(Failure::Icv)
        );
        assert_eq!(
            decrypt(&tk, &[0; 6], &mut sealed.clone()),
            Err(Failure::Icv)
        );
        let mut legacy = sealed.clone();
        legacy[3] &= !0x20;
        assert_eq!(decrypt(&tk, &ta, &mut legacy), Err(Failure::NoExtendedIv));
        assert_eq!(
            decrypt(&tk, &ta, &mut sealed[..11].to_vec()),
            Err(Failure::Short)
        );
    }
}
