// Copyright 2008, Joe Tsai. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>


/* Helper macros */
#define FUNC_PRINT_RETURN(fn, st, rc) { fn(); printf(st); return rc; }
#define FUNC_RETURN(fn, rc) { fn(); return rc; }
#define PRINT_RETURN(st, rc) { printf(st); return rc; }
#define SWAP(x, y) { (x) ^= (y); (y) ^= (x); (x) ^= (y); }
#define BIT16_LO(x) (((x) >>  0) & 0xFFFF)
#define BIT16_HI(x) (((x) >> 16) & 0xFFFF)
#define HEX2BIN(x) (isalpha(x) ? 10+tolower(x)-'a' : (x)-'0')
#define MAX(x,y) ((x) > (y) ? (x) : (y))


/* The subkeys - preloaded with the hex-digits of PI */
uint16_t arr_key[18];
uint16_t arr_p[18] = {
    0x243F, 0x6A88, 0x85A3, 0x08D3, 0x1319, 0x8A2E, 0x0370, 0x7344, 0xA409,
    0x3822, 0x299F, 0x31D0, 0x082E, 0xFA98, 0xEC4E, 0x6C89, 0x4528, 0x21E6,
};
uint16_t arr_s1[16] = {
    0x38D0, 0x1377, 0xBE54, 0x66CF, 0x34E9, 0x0C6C, 0xC0AC, 0x29B7,
    0xC97C, 0x50DD, 0x3F84, 0xD5B5, 0xB547, 0x0917, 0x9216, 0xD5D9,
};
uint16_t arr_s2[16] = {
    0x8979, 0xD131, 0x0BA6, 0x98DF, 0xB5AC, 0x2FFD, 0x72DB, 0xD01A,
    0xDFB7, 0xB8E1, 0xAFED, 0x6A26, 0x7E96, 0xBA7C, 0x9045, 0xF12C,
};
uint16_t arr_s3[16] = {
    0x7F99, 0x24A1, 0x9947, 0xB391, 0x6CF7, 0x0801, 0xF2E2, 0x858E,
    0xFC16, 0x6369, 0x20D8, 0x7157, 0x4E69, 0xA458, 0xFEA3, 0xF493,
};
uint16_t arr_s4[16] = {
    0x3D7E, 0x0D95, 0x748F, 0x728E, 0xB658, 0x718B, 0xCD58, 0x8215,
    0x4AEE, 0x7B54, 0xA41D, 0xC25A, 0x59B5, 0x9C30, 0xD539, 0x2AF2,
};


/* Global constants */
const char help_msg[] = (
    "This program will generate the P and S subkeys for a 32-bit block sized\n"
    "version of the BlowFish cipher developed by Bruce Schneier in 1993.\n\n"
);


int get_input();
int put_output();
void blowfish_keygen();
uint32_t blowfish_encrypt(uint32_t data);
uint16_t blowfish_feistel(uint16_t data);


int main(int argc, char* argv[]) {
    // Get the seed-key
    if (get_input())
        return -1;

    // Generate the BlowFish32 subkeys
    blowfish_keygen();

    // Output the subkeys
    if (put_output())
        return -1;

    return 0;
}


// Read a hexadecimal string from the user to use as the initial seed in the
// key generation routine. If the hex-string is less than 72 bytes, then the
// input key will be extended to fill the full key length. If the length is
// greater than 72 bytes, then the key will be compacted by XORing the remaining
// bytes with the existing bytes in a round-robin approach.
int get_input() {
    int idx;
    bool ok = false;
    while (!ok) {
        printf("Enter seed-key in hexadecimal (Ex: 573BE15A): ");

        // Read line from stdin
        char* line = NULL;
        size_t len = 0;
        if (getline(&line, &len, stdin) == -1)
            PRINT_RETURN("Could not read line\n", -1);
        strtok(line, "\r\n");

        // Verify that the key is okay
        int clen = strlen(line);
        ok = (clen > 0);
        for (idx = 0; idx < clen; idx++)
            ok = (ok && isxdigit(line[idx]));

        // Parse the key (handles key extending and compacting)
        int klen = sizeof(arr_key);
        memset(arr_key, '\0', klen);
        uint8_t* _arr_key = (uint8_t*)arr_key;
        if (ok) {
            for (idx = 0; idx < MAX(clen, klen*2); idx++) {
                int shift = (idx%2) ? 0 : 4;
                _arr_key[(idx/2) % klen] ^= HEX2BIN(line[idx % clen]) << shift;
            }
        }
        free(line);
    }
    return 0;
}


// Write to an output file called key.h that can be directly imported by the
// the various MikroC projects that share the same key.
int put_output() {
    int idx;
    FILE* out = NULL;
    void ret_func() {
        if (out != NULL)
            fclose(out);
    }

    printf("\nWriting output key file...\n");

    // Open the key file
    out = fopen("key.h", "w");
    if (out == NULL)
        FUNC_PRINT_RETURN(ret_func, "Could not open output file\n", -1);

    // Helper macro to print an array
    #define _PRINT_ARRAY(arr, cnt, err) {                                      \
        err |= (fprintf(                                                       \
            out, "const uint16_t %s[%d] = {\n    ", #arr, cnt                  \
        ) < 0);                                                                \
        for (idx = 0; idx < cnt/2; idx++)                                      \
            err |= (fprintf(out, "0x%04X, ", arr[idx]) < 0);                   \
        err |= (fprintf(out, "\n    ") < 0);                                   \
        for (idx = cnt/2; idx < cnt; idx++)                                    \
            err |= (fprintf(out, "0x%04X, ", arr[idx]) < 0);                   \
        err |= (fprintf(out, "\n};\n") < 0);                                   \
    }

    // Print the key file
    int err = (fprintf(out, "// The BlowFish32 cipher subkeys\n") < 0);
    _PRINT_ARRAY(arr_p, 18, err);
    _PRINT_ARRAY(arr_s1, 16, err);
    _PRINT_ARRAY(arr_s2, 16, err);
    _PRINT_ARRAY(arr_s3, 16, err);
    _PRINT_ARRAY(arr_s4, 16, err);
    if (err)
        FUNC_PRINT_RETURN(ret_func, "Failure to write to key file\n", -1);

    // Clean-up macro usage
    #undef _PRINT_ARRAY

    FUNC_RETURN(ret_func, 0);
}


// Perform the key schedule for BlowFish32. This is esentially the encryption of
// a zero-block and using the result for successive values of the P and S
// subkeys until all subkeys have been filled out. The initial P keys are seeded
// with the key obtained from the user.
void blowfish_keygen() {
    size_t idx;

    // Initial block to encrypt
    int32_t block = 0x00000000;

    // XOR the key with the P subkey to get the first permutation
    for (idx = 0; idx < 18; idx++) {
        arr_p[idx] = arr_p[idx] ^ arr_key[idx];
    }

    // Complete the generation of the P subkey
    for (idx = 0; idx < 18; idx += 2) {
        block = blowfish_encrypt(block);
        arr_p[idx+0] = BIT16_HI(block);
        arr_p[idx+1] = BIT16_LO(block);
    }

    // Complete the generation of the S subkeys
    size_t sidx;
    for (sidx = 0; sidx < 4; sidx++) {
        uint16_t* arr_sx = NULL;
        switch (sidx) {
        case 0: arr_sx = arr_s1; break;
        case 1: arr_sx = arr_s2; break;
        case 2: arr_sx = arr_s3; break;
        case 3: arr_sx = arr_s4; break;
        }

        for (idx = 0; idx < 16; idx += 2) {
            block = blowfish_encrypt(block);
            arr_sx[idx+0] = BIT16_HI(block);
            arr_sx[idx+1] = BIT16_LO(block);
        }
    }
}


// Run BlowFish32 encryption for a single 4-byte block.
uint32_t blowfish_encrypt(uint32_t data) {
    uint16_t data_hi = BIT16_HI(data);
    uint16_t data_lo = BIT16_LO(data);

    int idx;
    for (idx = 0; idx < 16; idx++) {
        data_hi ^= arr_p[idx];
        data_lo ^= blowfish_feistel(data_hi);
        SWAP(data_hi, data_lo);
    }
    SWAP(data_hi, data_lo);
    data_hi ^= arr_p[16];
    data_lo ^= arr_p[17];

    return ((uint32_t)data_hi << 16) | data_lo;
}


// Compute the value of the Feistel function for BlowFish32.
uint16_t blowfish_feistel(uint16_t data) {
    uint8_t d1 = (data >> 0)  & 0x0F;
    uint8_t d2 = (data >> 4)  & 0x0F;
    uint8_t d3 = (data >> 8)  & 0x0F;
    uint8_t d4 = (data >> 12) & 0x0F;
    return ((arr_s1[d1] + arr_s2[d2]) ^ arr_s3[d3]) + arr_s4[d4];
}
