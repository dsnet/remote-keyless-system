// Copyright 2008, Joe Tsai. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

#ifndef _CRYPTO_BLOWFISH_H
#define _CRYPTO_BLOWFISH_H

#include "types.h"


/* Helper macros */
#define SWAP(x, y) { (x) ^= (y); (y) ^= (x); (x) ^= (y); }
#define BIT16_LO(x) (((x) >>  0) & 0xFFFF)
#define BIT16_HI(x) (((x) >> 16) & 0xFFFF)


/* Global variables */
static const uint16_t* _key_p;
static const uint16_t* _key_s1;
static const uint16_t* _key_s2;
static const uint16_t* _key_s3;
static const uint16_t* _key_s4;


// HACK(jtsai): I could not figure out a way to make an external library be
//  importable into MikroC except to include an external header file. When you
//  include both the header files and add the C files to the project, MikroC
//  fails to compile the project. For this reason, I broke the practice of
//  seperating function prototypes and code.
void blowfish_setkeys(
    const uint16_t* p,
    const uint16_t* s1,
    const uint16_t* s2,
    const uint16_t* s3,
    const uint16_t* s4
);
uint32_t blowfish_encrypt(uint32_t data);
uint32_t blowfish_decrypt(uint32_t data);
uint16_t blowfish_feistel(uint16_t data);


// Set the BlowFish32 subkeys that will be used for all encryption and
// decryption operations. In order to encrypt or decrypt with a different key,
// this function must be called and loaded with a new set of keys.
void blowfish_setkeys(
    const uint16_t* p,
    const uint16_t* s1,
    const uint16_t* s2,
    const uint16_t* s3,
    const uint16_t* s4
) {
    _key_p = p;
    _key_s1 = s1;
    _key_s2 = s2;
    _key_s3 = s3;
    _key_s4 = s4;
}


// Run BlowFish32 encryption for a single 4-byte block.
uint32_t blowfish_encrypt(uint32_t data) {
    short idx;
    uint16_t data_hi = BIT16_HI(data);
    uint16_t data_lo = BIT16_LO(data);

    for (idx = 0; idx < 16; idx++) {
        data_hi ^= _key_p[idx];
        data_lo ^= blowfish_feistel(data_hi);
        SWAP(data_hi, data_lo);
    }
    SWAP(data_hi, data_lo);
    data_hi ^= _key_p[16];
    data_lo ^= _key_p[17];

    return ((uint32_t)data_hi << 16) | data_lo;
}


// Run BlowFish32 decryption for a single 4-byte block.
uint32_t blowfish_decrypt(uint32_t data) {
    short idx;
    uint16_t data_hi = BIT16_HI(data);
    uint16_t data_lo = BIT16_LO(data);

    data_hi ^= _key_p[16];
    data_lo ^= _key_p[17];
    SWAP(data_hi, data_lo);
    for (idx = 15; idx >= 0; idx--) {
        SWAP(data_hi, data_lo);
        data_lo ^= blowfish_feistel(data_hi);
        data_hi ^= _key_p[idx];
    }

    return ((uint32_t)data_hi << 16) | data_lo;
}


// Compute the value of the Feistel function for BlowFish32.
uint16_t blowfish_feistel(uint16_t data) {
    short d1, d2, d3, d4;
    d1 = (data >> 0)  & 0x0F;
    d2 = (data >> 4)  & 0x0F;
    d3 = (data >> 8)  & 0x0F;
    d4 = (data >> 12) & 0x0F;
    return ((_key_s1[d1] + _key_s2[d2]) ^ _key_s3[d3]) + _key_s4[d4];
}


#endif /* _CRYPTO_BLOWFISH_H */
