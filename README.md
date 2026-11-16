# CryptographyApp

Desktop app in C++ and Qt for encrypting text files and sending them to
another instance over TCP. A university project.

It has three ciphers to choose from: Double Transposition, A5/2, and a CFB
mode I built on top of A5/2.

## What it does

- Encrypt or decrypt a .txt file by hand
- Watch a folder and encrypt new files as they appear (runs in its own thread)
- Send an encrypted file over TCP. The receiver checks the MD5 hash of the
  message before decrypting it

## Building

Windows only. Visual Studio 2022, Qt 6.9.1 (msvc2022_64), C++17.
Open `CryptoProject.sln`, set your Qt path in the Qt VS Tools settings, build.

## Using it

Open Settings first and pick the folder to watch and the output folder. Then
choose an algorithm and enter the key:

- Double Transposition: row key and column key, each a permutation of 0..N-1
- A5/2: 8 key bytes in hex and a frame number in hex (max 0x3FF)
- CFB: same as A5/2, plus an IV as comma-separated bytes

To send a file, click Receive in one instance (it waits for a connection),
then pick a file and click Send in another. Both sides need the same
algorithm and key.
