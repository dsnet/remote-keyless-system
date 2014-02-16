// Copyright 2008, Joe Tsai. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE.md file.

/*
Project name:
    Remote Keyless System - Transmitter
Description:
    This is the receiver part of the remote keyless system project. The receiver
    continuously waits for a signal from the transmitter. The messages need to
    be encrypted with BlowFish32 and verified using a CRC8 checksum. The system
    supports up to 16 channels, each of which have their own associated rolling
    codes. However, all 16 channels share the same encryption key. Thus, it is
    not secure to simply invalidate a channel in the event of a lost remote.
    For easier debugging of operations, data and commands received by the device
    are displayed on a 4x20 character LCD module.
Configuration:
    Microcontroller:   PIC16F877A
    Oscillator:        HS, 8.00 MHz
    External Modules:  RF 434 MHz transmitter, 4x20 character LCD
    Compiler:          MikroC 8.0
Notes:
    A variation of the BlowFish cipher is used in this project. The cipher's
    block size was reduced from 64-bits to 32-bits to reduce memory usage.
    Thanks to Bruce Schneier who developed the original cipher in 1993.
 */

#include "../crypto/crc.h"
#include "../crypto/blowfish.h"
#include "../key_gen/key.h"


/* Global constants */
const char text_cmd1[] = "Command";
const char text_res1[] = "Channel 0x0X Reset";
const char text_res2[] = "Master Reset";
const char text_ttl1[] = "Invalid PassCode";
const char text_ttl2[] = "Store PassCode";
const char text_lbl1[] = "Code:";
const char text_lbl2[] = "Entry Key:";
const char text_lbl3[] = "Channel:";
const char text_lbl4[] = "Abort?";
const char text_lbl5[] = "Completed!";
const char text_lbl6[] = "Canceled!";

enum command { CMD_NORMAL, CMD_STORE_CHAN, CMD_RESET_CHAN, CMD_RESET_ALL };

// HACK(jtsai): The Manchester library fails to synchronize properly a vast
//  majority of the time. This normally requires the system to be continually
//  power cycled until the library can get a lock on the incoming signal.
//  Since we know exactly what the incoming signal should look like, we can
//  directly modify the global variables in the library and skip syncing.
const short SYNC_HACK = 1;

// HACK(jtsai): The Manchester library provides no framing. Thus, each byte is
//  received individually. In order to hack in our own framing, we reserve the
//  byte 0b10010110 as the start marker.
const uint8_t FRAME_MARK = 0b10010110;

// The rolling code maintains a moving window that protects against replay
// attacks. However, there is the possibility that the transmitter and receiver
// can get out of sync if the transmitter increments its rolling code too often
// without the receiver ever getting any messages. Thus, there is a window where
// future codes are acceptable by the receiver.
const int ROLLING_WINDOW = 0x0400;

// The EEPROM addresses where the code arrays and enable bits are stored.
const short MAX_CHANS = 16;
const uint8_t ADDRESS_CODE = 0x00;
const uint8_t ADDRESS_STATE = MAX_CHANS*4;

// Maximum number of times to try unlatching the bolt.
const short MAX_BOLT_RETRY = 100;


void manchester_synchronize();
void receive_code(uint8_t* data);
void process_code(uint8_t* data);
void process_load(uint8_t* data, uint32_t code, short chan);
void process_store(uint8_t* data, uint32_t code, short chan);
void process_reset(short chan);
void bolt_unlock();
uint8_t read_channel_state(short chan);
uint32_t read_channel_code(short chan);
void write_channel_state(short chan, uint8_t state);
void write_channel_code(short chan, uint32_t code);
void lcd_const(short row, short col, const char* data);
void lcd_hex(short row, short col, short val);
void lcd_hexdump(short row, short col, uint8_t* data, short num);


void main() {
    uint8_t data[6];

    // Define inputs and outputs
    PORTC = 0x00;
    TRISB = 0x00;
    TRISC = 0x00;
    TRISD = 0x07;

    // Setup the LCD module
    lcd_init(&PORTB);
    lcd_cmd(LCD_CLEAR);
    lcd_cmd(LCD_CURSOR_OFF);
    lcd_cmd(LCD_TURN_OFF);

    // Configure the BlowFish32 cipher
    blowfish_setkeys(arr_p, arr_s1, arr_s2, arr_s3, arr_s4);

    // Configure the Manchester decoder
    man_receive_config(&PORTB, 0);

    // Synchronize the Manchester decoder
    if (SYNC_HACK) {
        // HACK(jtsai): I have no idea what these variables do, but they are in
        //  the global variable space of the Manchester library. Setting them to
        //  these values seems to magically make the library work.
        FULLBITS = 0x80;
        HALFBITS = 0x40;
    } else {
        // Synchronize if the frequency constants aren't already known
        PORTD = 0xE0; // Turn on all LEDs
        manchester_synchronize();
        PORTD = 0x00; // Turn off all LEDs
    }

    // Main event loop
    while (1) {
        receive_code(data);
        process_code(data);
    }
}


// Since the Manchester library does not simply start-up in a working state, it
// needs to be synchronized by receiving messages from the transmitters.
// This is achieved by simply broadcasting a valid message repeatedly from the
// remotes until synchronization occurs. This function attempts to collect the
// 6-byte messages that the transmitters send and verify that the CRC is valid.
void manchester_synchronize() {
    const short MAX_ERR_CNT = 8;
    short idx, ok;
    unsigned short err, err_cnt;
    uint8_t data[6];

    while (1) {
        if ((man_receive(&err) == FRAME_MARK) && !err) {
            // Get the 6 byte data message
            ok = 1;
            for (idx = 0; idx < 6; idx++) {
                data[idx] = man_receive(&err);
                if (err) {
                    err_cnt++;
                    ok = 0;
                    break;
                }
            }

            // If no transmission error, then break
            if (ok == 1 && (crc_ccitt(data, 5) == data[5]))
                break;
        } else {
            // If too many errors, try to synchronize again
            err_cnt++;
            if (err_cnt > MAX_ERR_CNT) {
                man_synchro();
                err_cnt = 0;
            }
        }
    }
}


// This function blocks until a valid 6-byte message from a transmitter is
// received. When this function returns, the payload in the data pointer is
// guaranteed to have passed the CRC check. The data pointer must point to a
// block of memory that is at least 6-bytes long.
void receive_code(uint8_t* data) {
    short idx, ok;
    unsigned short err;

    // Blocking receive
    while (1) {
        // Poll for frame marker
        while (man_receive(&err) != FRAME_MARK && !err) {}

        // Get the 6 byte data message
        ok = 1;
        for (idx = 0; idx < 6; idx++) {
            data[idx] = man_receive(&err);
            if (err) {
                ok = 0;
                break;
            }
        }

        // Ensure no transmission error
        if (ok && (crc_ccitt(data, 5) == data[5]))
            return;
    }
}


// Based on the pin configurations, determine the type of command to run.
// Parse out the code and channel values and decrypt the rolling code.
void process_code(uint8_t* data) {
    uint8_t cmd = CMD_NORMAL;
    uint32_t code = *((uint32_t*)data);
    short chan = data[4] % MAX_CHANS;

    // Display LCD message
    lcd_cmd(LCD_TURN_ON);
    lcd_cmd(LCD_RETURN_HOME);

    // Decrypt the rolling code
    code = blowfish_decrypt(code);

    // Get command input
    if (!PORTD.F0 && PORTD.F1) {
        cmd = CMD_STORE_CHAN;
    } else if (PORTD.F0 && !PORTD.F1) {
        cmd = CMD_RESET_CHAN;
    } else if (PORTD.F0 && PORTD.F1) {
        cmd = CMD_RESET_ALL;
    }

    // Process the command
    if (cmd == CMD_NORMAL) {
        process_load(data, code, chan);
    } else if (cmd == CMD_STORE_CHAN) {
        process_store(data, code, chan);
    } else if (cmd == CMD_RESET_CHAN || cmd == CMD_RESET_ALL) {
        process_reset((cmd == CMD_RESET_ALL) ? -1 : chan);
    }

    // Stop display
    lcd_cmd(LCD_CLEAR);
    lcd_cmd(LCD_TURN_OFF);
    PORTD = 0x00;
}


// This is the standard code-path that process_code() takes. It will verify that
// the given channel and code are legit. If so, it will proceed to unlock the
// door bolt.
void process_load(uint8_t* data, uint32_t code, short chan) {
    short invalid = 0;

    // Check that the code is legit
    invalid |= (read_channel_state(chan) != 0xFF);
    invalid |= (code - read_channel_code(chan) >= ROLLING_WINDOW);

    // Display system status
    if (invalid) {
        PORTD = 0x30; // Show LEDs
        lcd_const(1, 3, text_ttl1);
    } else {
        PORTD = 0x50; // Show LEDs
        lcd_const(1, 2, text_ttl1);
        lcd_chr(1,2,' ');
        lcd_chr(1,3,' ');
        lcd_chr(1,4,'V');
    }
    lcd_const(2, 1, text_lbl1);
    lcd_hexdump(2, 9, data, 6);
    lcd_const(3, 1, text_lbl2);
    lcd_hexdump(3, 13, (uint8_t*)code, 4);
    lcd_const(4, 1, text_lbl3);
    lcd_chr(4, 19, '0');
    lcd_hex(4, 20, chan);

    // Unlock the bolt
    if (invalid) {
        delay_ms(5000);
    } else {
        write_channel_code(chan, code+1);

        bolt_unlock();
        delay_ms(3000);
    }
}


// This command path stores the transmitted rolling code for a given channel
// and then activates that channel.
void process_store(uint8_t* data, uint32_t code, short chan) {
    // Display system status
    PORTD = 0x90; // Show LEDs
    lcd_const(1, 6, text_cmd1);
    lcd_chr(1, 14, '0');
    lcd_chr(1, 15, '1');
    lcd_const(2, 4, text_ttl2);
    lcd_const(3, 1, text_lbl2);
    lcd_hexdump(3, 13, (uint8_t*)code, 4);
    lcd_const(4, 1, text_lbl3);
    lcd_chr(4, 19, '0');
    lcd_hex(4, 20, chan);

    // Store the code and activate the channel
    write_channel_code(chan, code+1);
    write_channel_state(chan, 0xFF);

    delay_ms(5000);
}


// This command path either resets all channels or resets only a given channel.
// If the channel argument is negative, then all channels are reset.
void process_reset(short chan) {
    short idx, abort;

    // Display system status
    PORTD = 0x50; // Show LEDs
    lcd_const(1, 6, text_cmd1);
    lcd_chr(1, 14, '1');
    lcd_chr(1, 15, (chan == -1) ? '1' : '0');
    if (chan >= 0) {
        lcd_const(2, 2, text_res1);
        lcd_hex(2, 13, chan);
    } else {
        lcd_const(2, 5, text_res2);
    }

    // Abort countdown
    lcd_const(3, 8, text_lbl4);
    lcd_chr(4, 10, '0');
    abort = 0;
    for (idx = 5; idx >= 0 && !abort; idx--) {
        lcd_hex(4, 11, idx);
        delay_ms(1000);
        abort = (PORTD.F0 == 0 && PORTD.F1 == 0);
    }
    lcd_chr(4, 10, ' ');
    lcd_chr(4, 11, ' ');

    // Perform reset
    if (abort) {
        if (chan >= 0) {
            write_channel_state(chan, 0x00);
        } else {
            for (idx = 0; idx < MAX_CHANS; idx++) {
                write_channel_state(idx, 0x00);
            }
        }
    }

    // Display result
    if (abort) {
        PORTD = 0x30; // Show LEDs
        lcd_const(3, 6, text_lbl6);
    } else {
        PORTD = 0x90; // Show LEDs
        lcd_const(3, 6, text_lbl5);
    }

    delay_ms(3000);
}


// Active the drive motors to unlock the bolt and relock the bolt.
void bolt_unlock() {
    short num_retry = 0;

    // If the latch is not already open
    if (PORTD.F2 == 0) {
        // Activate the bolt unlocker
        PORTC = 0x80;
        delay_ms(150);

        // Deactivate the bolt unlocker
        PORTC = 0x00;
        delay_ms(300);

        // Let unlocker run while the door is still locked
        while (PORTD.F2 == 0) {
            PORTC = 0x80; // Activate the bolt unlocker
            if (num_retry > MAX_BOLT_RETRY)
                break;
            delay_ms(5);
            num_retry++;
        }

        // Deactivate the bolt unlocker
        PORTC = 0x00;
        delay_ms(1000);
    }

    // Activate bolt locker, wait delay, then deactivate
    PORTC = 0x40;
    delay_ms(1000);
    PORTC = 0x00;

    PORTD = (PORTD.F2 == 0) ? 0x30 : 0x90; // Show LEDs
}


// Read the channel state from EEPROM.
uint8_t read_channel_state(short chan) {
    delay_ms(20);
    return eeprom_read(ADDRESS_STATE+chan);
}


// Read the channel rolling code from EEPROM in native endian format.
uint32_t read_channel_code(short chan) {
    short idx;
    uint32_t code;
    uint8_t* _code = (uint8_t*)(&code);
    uint16_t offset = ADDRESS_CODE + chan*4;

    for (idx = 0; idx < 4; idx++) {
        delay_ms(20);
        _code[idx] = eeprom_read(offset + idx);
    }

    return code;
}


// Write the channel state to EEPROM.
void write_channel_state(short chan, uint8_t state) {
    delay_ms(20);
    eeprom_write(ADDRESS_STATE+chan, state);
}


// Write the channel rolling code to EEPROM in native endian format.
void write_channel_code(short chan, uint32_t code) {
    short idx;
    uint8_t* _code = (uint8_t*)(&code);
    uint16_t offset = ADDRESS_CODE + chan*4;

    for (idx = 0; idx < 4; idx++) {
        delay_ms(20);
        eeprom_write(offset + idx, _code[idx]);
    }
}


// Wrapper around lcd_out() that can output strings that are stored in ROM.
void lcd_const(short row, short col, const char* data) {
    char buf[20];
    short idx = 0;
    do {
        buf[idx] = data[idx];
    } while(buf[idx++]);
    lcd_out(row, col, buf);
}


// Wrapper around lcd_chr() that outputs a hexadecimal value.
void lcd_hex(short row, short col, short val) {
    lcd_chr(row, col, (val < 10) ? ('0' + val) : ('A' + val - 10));
}


// Wrapper around lcd_out() that hexdumps the num bytes in data.
void lcd_hexdump(short row, short col, uint8_t* data, short num) {
    short idx;
    uint8_t hex_lo, hex_hi;

    for (idx = 0; idx < num; idx++) {
        lcd_hex(row, col, (data[idx] >> 0) & 0x0F);
        col++;
        lcd_hex(row, col, (data[idx] >> 4) & 0x0F);
        col++;
    }
}
