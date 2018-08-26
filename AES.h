/**
 *
 * This code was "inspired" by Bouncycastle.

This is the license from bouncycastle:

Copyright (c) 2000 - 2017 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

In the spirit of the above license, this implementation retains the same licensing terms, but is

Copyright 2017 Nicholas Sayer

This version has been flattened to support only 128 bit AES.

ECB decryption support is optional, as OFB mode and CMAC need only AES ECB encrypt to both encrypt and decrypt.

 */

#include <stdint.h>
#include <stdlib.h>

#define KEY_SIZE (16)
#define BLOCK_SIZE (16)

void setKey(uint8_t* key);
void encrypt_ECB(uint8_t* block);
//void decrypt_ECB(uint8_t* block);

// IV is BLOCK_SIZE long
void init_OFB(uint8_t* iv);

// OFB decryption uses the encrypt method.
uint8_t encrypt_OFB_byte(uint8_t data);
void encrypt_OFB(uint8_t* buf, size_t buf_length);

void CMAC(uint8_t *buf, size_t buf_length, uint8_t *sigbuf);

// generate random numbers using AES CMAC with a seed periodically saved to EEPROM.
void PRNG(uint8_t *buf, size_t buf_length);

// Initialize the PRNG key with a buffer of per-instance uniqueness
// (we'll use the chip serial information)
void PRNG_init(uint8_t *seed_buf, size_t seed_len);
