// Copyright 2008, Joe Tsai. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

#ifndef _CRYPTO_CRC_H
#define _CRYPTO_CRC_H

#include "types.h"


// HACK(jtsai): I could not figure out a way to make an external library be
//  importable into MikroC except to include an external header file. When you
//  include both the header files and add the C files to the project, MikroC
//  fails to compile the project. For this reason, I broke the practice of
//  seperating function prototypes and code.
uint8_t crc_ccitt(uint8_t* data, short num);


// Compute the CRC-8 according to the CCITT polynomial of 0x8D.
uint8_t crc_ccitt(uint8_t* data, short num) {
    short byte_idx, bit_idx;
    uint8_t _crc, _dat;

    const uint8_t poly = 0x8D;
    uint8_t crc = 0xFF;

    // Process all data bytes
    for (byte_idx = 0; byte_idx < num; byte_idx++) {
        _dat = data[byte_idx];
        for (bit_idx = 0; bit_idx < 8; bit_idx++) {
            _crc = crc;
            crc <<= 1;
            if (_dat & 0x80)
                crc++;
            _dat <<= 1;
            if (_crc & 0x80)
                crc ^= poly;
        }
    }

    // Augment 8 zero bits
    for (bit_idx = 0; bit_idx < 8; bit_idx++) {
        _crc = crc;
        crc = crc << 1;
            if (_crc & 0x80)
            crc ^= poly;
    }

    return crc;
}


#endif /* _CRYPTO_CRC_H */
