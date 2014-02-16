// Copyright 2008, Joe Tsai. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

#ifndef _CRYPTO_TYPES_H
#define _CRYPTO_TYPES_H


// HACK(jtsai): MikroC apparently does not treat equivalent typdefs as equal
//  and runs into all sorts of strange compiler errors. Use C preprocessor
//  macros to define the integer types common to Unix.

#define int8_t  signed short
#define int16_t signed int
#define int32_t signed long

#define uint8_t  unsigned short
#define uint16_t unsigned int
#define uint32_t unsigned long


#endif /* _CRYPTO_TYPES_H */
