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

// For AES-128, it's a coincidence that the key size and block size is the same.
#define KEY_SIZE (16)
#define BLOCK_SIZE (16)

// Set key for all AES operations. Buffer is KEY_SIZE long.
void setKey(uint8_t* key);

// Perform an AES ECB block encrytion (call setKey first). Block is BLOCK_SIZE long.
void encrypt_ECB(uint8_t* block);
// We don't use ECB decryption, which saves us space in flash.
//void decrypt_ECB(uint8_t* block);

