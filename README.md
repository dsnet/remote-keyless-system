# Remote Keyless System #

## Introduction ##

Ever get tired of fumbling around your wallet looking for your room card key? Worse yet, to realize that you left the key in your room to begin with? What if you could control access to your room wirelessly? Now you can!

This remote keyless entry system consists of a wireless receiver mechanism that listens for passcodes sent by individual transmitter fobs. The transmitters send codes in encrypted form with a rolling code. This prevents any form of replay attack.

[![system-demo](http://code.digital-static.net/remote-keyless-system/raw/tip/media/system-full.jpg)](http://www.youtube.com/watch?v=MCNyj44IE78)
(Click above image for demonstration video)


## Implementation ##

*To be continued*


## File Structure ##

* **board**: Circuit board schematics or PCB layouts
* **media**: Multimedia files such as photographs or videos
* **mikroc**: C sub-projects targeted at the microcontroller realm
* **mikroc/receiver**: Project for receiving signals and unlocking the door
* **mikroc/transmitter**: Project for transmitting signals
* **mikroc/crypto**: Library for performing BlowFish32 encryption
* **mikroc/key_gen**: Program to generate BlowFish32 subkeys from a seed key