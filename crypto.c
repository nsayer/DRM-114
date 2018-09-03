
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
#include "AES.h"
#include "key_protection.h"

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

