
/*

    DRM-114
    Copyright (C) 2018-2019 Nicholas W. Sayer

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

/*
 * An encrypted message looks like this:
 *
 * 16 bytes (KEY_SIZE) of protected key
 * 16 bytes (BLOCK_SIZE) of IV
 * 16 bytes (BLOCK_SIZE) of encrypted MAC (that is, part of the ciphertext)
 * and the rest of it is ciphertext
 */

#include <stdlib.h>
#include <string.h>
#include <avr/eeprom.h>
#include "AES.h"
#include "crypto.h"
#include "key_protection.h"

// This is a CMAC constant related to the key size.
#define RB (0x87)

#define MAX(a,b) (((a)<(b))?(b):(a))


static uint8_t iv_block[BLOCK_SIZE];
static uint8_t iv_pos;

static inline void init_OFB(uint8_t* iv) {
        memcpy(iv_block, iv, sizeof(iv_block));
        iv_pos = BLOCK_SIZE + 1; // force an initial restart
}

// Turns out that for OFB mode, we can encrypt and decrypt with the exact same method.
// This method allows for streaming OFB mode. You can call this over and over
// after calling init_OFB to initialize things.
static inline uint8_t encrypt_OFB_byte(uint8_t data) {
        if (iv_pos >= BLOCK_SIZE) {
                // restart
                encrypt_ECB(iv_block);
                iv_pos = 0;
        }
        return data ^ iv_block[iv_pos++];
}

static void encrypt_OFB(uint8_t* buf, size_t buf_length) {
        for(int i = 0; i < buf_length; i++) {
                buf[i] = encrypt_OFB_byte(buf[i]);
        }
}

static uint8_t leftShiftBlock(uint8_t* ptr, size_t block_length) {
        uint8_t carry = 0;
        for(int i = block_length - 1; i >= 0; i--) {
                uint8_t save_carry = (ptr[i] & 0x80)?1:0;
                ptr[i] <<= 1;
                ptr[i] |= carry;
                carry = save_carry;
        }
        return carry;
}

// perform an AES CMAC signature on the given buffer.
static void CMAC(uint8_t *buf, size_t buf_length, uint8_t *sigbuf) {
        uint8_t kn[BLOCK_SIZE];
        memset(kn, 0, BLOCK_SIZE); // start with 0.
        encrypt_ECB(kn);

        // First, figure out k1. That's a left-shift of "k0",
        // and if the top bit of k0 was 1, we XOR with RB.
        uint8_t save_carry = (kn[0] & 0x80) != 0;
        leftShiftBlock(kn, BLOCK_SIZE);
        if (save_carry)
                kn[BLOCK_SIZE - 1] ^= RB;

        if (buf_length % BLOCK_SIZE) {
                // We must now make k2, which is just the same thing again.
                save_carry = (kn[0] & 0x80) != 0;
                leftShiftBlock(kn, BLOCK_SIZE);
                if (save_carry)
                        kn[BLOCK_SIZE - 1] ^= RB;

        }

        memset(sigbuf, 0, BLOCK_SIZE); // start with 0.
        for(int i = 0; i < (((buf_length - 1) / BLOCK_SIZE) * BLOCK_SIZE); i += BLOCK_SIZE) {
                for(int j = 0; j < BLOCK_SIZE; j++)
                        sigbuf[j] ^= buf[i + j];
                encrypt_ECB(sigbuf); // Now roll the intermediate value through ECB.
        }

        // Now we do the last block.
        uint16_t start = ((buf_length - 1) / BLOCK_SIZE) * BLOCK_SIZE;
        for(int i = start; i < buf_length; i++)
                sigbuf[i - start] ^= buf[i];

        // If there's any empty bytes at the end, then xor the first "unused" one with
        // a trailer byte.
        if (buf_length - start < BLOCK_SIZE)
                sigbuf[buf_length - start] ^= 0x80;

        // Now xor in kn.
        for(int i = 0; i < BLOCK_SIZE; i++)
                sigbuf[i] ^= kn[i];

        encrypt_ECB(sigbuf); // Now roll THAT and the result is the answer.
}

static uint8_t prng_counter[BLOCK_SIZE];
static uint8_t prng_block[BLOCK_SIZE];
static uint8_t prng_key[KEY_SIZE];
#define EEPROM_SEED_LOCATION ((uint8_t*)(0))

// This gets called at initialization time with some sort
// of unique data per instance (the chip serial number).
// We will turn that into the PRNG key.
void PRNG_init(uint8_t *seed_buf, size_t seed_len) {
        uint8_t temp_key[KEY_SIZE];
        memset(temp_key, 0, sizeof(temp_key));
        setKey(temp_key);
        CMAC(seed_buf, seed_len, prng_key);
        // read the seed counter
        for(int i = 0; i < sizeof(prng_block); i++)
                prng_counter[i] = eeprom_read_byte(EEPROM_SEED_LOCATION + i);
}

static void PRNG_update() {
        // write it back
        for(int i = 0; i < sizeof(prng_counter); i++)
                eeprom_update_byte(EEPROM_SEED_LOCATION + i, prng_counter[i]);
}

// We use AES ECB as a PRNG with a monotonic counter and a per-device perturbed PRNG key.
static void make_prng_block() {
        // increment it
        for(int i = sizeof(prng_counter) - 1; i >= 0; i--) {
                if (++prng_counter[i] != 0) break;
        }
        memcpy(prng_block, prng_counter, sizeof(prng_block));
        setKey(prng_key);
        encrypt_ECB(prng_block);
}

void PRNG(uint8_t *buf, size_t buf_length) {
        for(int i = 0; i < buf_length; i += sizeof(prng_block)) {
                make_prng_block();
                memcpy(buf + i, prng_block, MAX(sizeof(prng_block), buf_length - i));
        }
        PRNG_update();
}

// ct_length is the available length of the buffer on input, and the actual length of the ciphertext on
// output. The return is true if the encryption succeeded. The only way it can be false is if the
// output buffer isn't large enough to accommodate the ciphertext.
uint8_t encrypt_message(uint8_t* plaintext, size_t pt_length, uint8_t* ciphertext, size_t *ct_length) {

	if (*ct_length < pt_length + KEY_SIZE + BLOCK_SIZE * 2) return 0; // we'd throw an exception if we could

	PRNG(ciphertext, KEY_SIZE + BLOCK_SIZE); // make a random key and a random IV
	memcpy(ciphertext + KEY_SIZE + 2 * BLOCK_SIZE, plaintext, pt_length); // copy the plaintext into the right spot
	setKey(ciphertext);
	CMAC(plaintext, pt_length, ciphertext + KEY_SIZE + BLOCK_SIZE); // generate the MAC for the message
	init_OFB(ciphertext + KEY_SIZE); // set up the IV
	encrypt_OFB(ciphertext + KEY_SIZE + BLOCK_SIZE, pt_length + BLOCK_SIZE); // encrypt the MAC and plaintext
	protect_key(ciphertext, 1); // and, lastly, obfuscate the key
	*ct_length = pt_length + KEY_SIZE + BLOCK_SIZE * 2;
	return 1;
}

// pt_length is the available length of the plaintext buffer on input, and the actual length of the plaintext on
// output. The return is true if the decrypted message validates, false otherwise.
uint8_t decrypt_message(uint8_t* ciphertext, size_t ct_length, uint8_t* plaintext, size_t *pt_length) {
	if (ct_length < KEY_SIZE + BLOCK_SIZE * 2) return 0; // too short
	if (*pt_length < ct_length - (KEY_SIZE + BLOCK_SIZE * 2)) return 0; // output buffer too short
	protect_key(ciphertext, 0); // get back the correct key
	setKey(ciphertext);
	init_OFB(ciphertext + KEY_SIZE);
	encrypt_OFB(ciphertext + KEY_SIZE + BLOCK_SIZE, ct_length - (KEY_SIZE + BLOCK_SIZE)); // Decrypt the MAC and plaintext
	uint8_t computed_mac[BLOCK_SIZE];
	CMAC(ciphertext + KEY_SIZE + BLOCK_SIZE * 2, ct_length - (KEY_SIZE + BLOCK_SIZE * 2), computed_mac); // calculate actual MAC
	uint8_t bad = 0;
	for(int i = 0; i < BLOCK_SIZE; i++) // compare computed to expected MAC.
		if (computed_mac[i] != ciphertext[i + KEY_SIZE + BLOCK_SIZE]) bad = 1; // do NOT break - side channel attack
	if (bad) return 0; // bad MAC

	// it's all good.
	*pt_length = ct_length - (KEY_SIZE + BLOCK_SIZE * 2);
	memcpy(plaintext, ciphertext + KEY_SIZE + BLOCK_SIZE * 2, *pt_length);
	return 1;
}
