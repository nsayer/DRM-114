/*

    DRM-114
    Copyright (C) 2018 Nicholas W. Sayer

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
    
  */


// ct_length is the available length of the buffer on input, and the actual length of the ciphertext on
// output. The return is true if the encryption succeeded (it can only fail if the buffer isn't long enough).
extern uint8_t encrypt_message(uint8_t* plaintext, size_t pt_length, uint8_t* ciphertext, size_t * ct_length);

// pt_length is the available length of the buffer on input, and the actual length of the plaintext on
// output. The return is true if the decrypted message validates, false otherwise.
extern uint8_t decrypt_message(uint8_t* ciphertext, size_t ct_length, uint8_t* plaintext, size_t * pt_length);

// Initialize the PRNG key with a buffer of per-instance uniqueness
// (we'll use the chip serial information)
void PRNG_init(uint8_t *seed_buf, size_t seed_len);
void PRNG(uint8_t *buf, size_t len);

