// Copyright 2008, Joe Tsai. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

/*
Project name:
    Remote Keyless System - Transmitter
Description:
    This implements the remote transmitter part of the remote keyless system.
    The transmitter sends an encrypted rolling code through the RF module using
    Manchester encoding. The message is protected by BlowFish32 encryption and
    verified using CRC8-CCITT checksums. The system supports up to 16 different
    channels that maintain their own rolling codes. The channel of the remote
    must be programmed in at flash time.
Configuration:
    Microcontroller:   PIC12F683
    Oscillator:        INT_RC, 8.00 MHz
    External Modules:  RF 434 MHz transmitter
    Compiler:          MikroC 8.0
Notes:
    A variation of the BlowFish cipher is used in this project. The cipher's
    block size was reduced from 64-bits to 32-bits to reduce memory usage.
    Thanks to Bruce Schneier who developed the original cipher in 1993.
*/

#include "../crypto/crc.h"
#include "../crypto/blowfish.h"
#include "../key_gen/key.h"


// The hard-coded channel number for this transmitter. The receiver keeps track
// of the rolling codes for each transmitter on a per-channel basis. The valid
// values for the channel number are from 0x00 to 0x0F inclusive.
const uint8_t CHAN_NUM = 0x00;

// HACK(jtsai): The Manchester library provides no framing. Thus, each byte is
//  received individually. In order to hack in our own framing, we reserve the
//  byte 0b10010110 as the start marker.
const uint8_t FRAME_MARK = 0b10010110;


uint32_t read_code();
void write_code(uint32_t code);
uint32_t transmit_code(uint32_t code, short cnt);
short valid_message(uint8_t* data, short num);


//The main function
void main() {
    uint32_t code;

    // Half second delay as an extended power up timer
    delay_ms(500);

    // Set program defaults
    INTCON     = 0x00;  // Disable interrupts
    ANSEL      = 0x00;  // Configure AN pins as digital
    CMCON0     = 0x07;  // Disable comparators
    OPTION_REG = 0x00;  // Enable pull-ups
    WPU        = 0x04;  // Define pull-up values
    TRISIO     = 0x04;  // Define inputs/outputs
    GPIO       = 0x00;  // Define default outputs
    OSCCON     = 0x75;  // Define oscillator settings

    // Configure the Manchester encoder
    man_send_config(&GPIO, 5);

    // Configure the BlowFish32 cipher
    blowfish_setkeys(arr_p, arr_s1, arr_s2, arr_s3, arr_s4);

    // Load the rolling code
    code = read_code();

    // Enable external interrupts
    INTCON.INTE = 1;
    while (1) {
        // Sleep until woken by external interrupt
        asm CLRWDT;
        asm SLEEP;
        asm NOP;

        // Debounce timer
        delay_ms(25);

        if (GPIO.F2 == 1) {
            code = transmit_code(code, 16);
            write_code(code);
        }

        // Clear interrupt flag
        INTCON.INTF = 0;
    }
}


// Read the current rolling code from EPPROM in native endianness.
uint32_t read_code() {
    short idx;
    uint32_t code;
    uint8_t* _code = (uint8_t*)(&code);

    for (idx = 0; idx < 4; idx++) {
        delay_ms(20);
        _code[idx] = eeprom_read(idx);
    }

    return code;
}


// Write the given rolling code to EPPROM in native endianness.
void write_code(uint32_t code) {
    short idx;
    uint8_t* _code = (uint8_t*)(&code);

    for (idx = 0; idx < 4; idx++) {
        delay_ms(20);
        eeprom_write(idx, _code[idx]);
    }
}


// Generate the message to transmit over the air. This function will
// automatically increment the rolling code and transmit the message cnt times.
uint32_t transmit_code(uint32_t code, short cnt) {
    int idx;
    uint8_t data[6];
    uint32_t block;

    // The message transmitted is the following 6-byte segment:
    //  +---+---+---+---+----------+-----+
    //  | rolling_code  | chan_num | crc |
    //  +---+---+---+---+----------+-----+
    //
    // It is essentially the encrypted rolling code, the channel number, and
    // the CRC8 value computed over the rolling_code and chan_num fields.
    // The endianness of the rolling_code field is the default endianness of the
    // MikroC compiler and must the same for both transmitter and receiver.
    // The segment above does not show the preceeding frame marker.

    // Power on the transmitter module
    GPIO.F4 = 1;

    // Form the transmission message
    data[5] = CHAN_NUM;
    do {
        code++; // Increment the code
        *((uint32_t*)data) = blowfish_encrypt(code); // Encrypt the code
        data[6] = crc_ccitt(data, 5); // Compute the CRC8
    } while (!valid_message(data, 6));

    // Send burst fire of transmission signals
    for (; cnt > 0; cnt--) {
        man_send(FRAME_MARK);
        delay_ms(5);
        for (idx = 0; idx < 6; idx++) {
            man_send(data[idx]);
            delay_ms(5);
        }
    }

    // Power off the transmitter module
    GPIO.F4 = 0;

    return code;
}


// Ensure that the frame marker does not appear in the message.
short valid_message(uint8_t* data, short num) {
    for (; num > 0; num--, data++)
        if ((*data) == FRAME_MARK)
            return 0;
    return 1;
}
