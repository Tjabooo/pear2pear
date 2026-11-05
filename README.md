# pear2pear

A small command-line file transfer tool written in Java. A sender and a receiver connect to a relay server and share a passkey; the file is encrypted end to end with AES-GCM, so the relay only forwards ciphertext. Inspired by the workflow of [croc](https://github.com/schollz/croc).

Hobby project, not audited. Don't rely on it for anything sensitive.

## Requirements
- JDK (any recent version; it only uses the standard library)

## Build
```bash
git clone https://github.com/Tjabooo/pear2pear.git
cd pear2pear/src
javac pear2pear/*.java
```
The commands below are run from the `src` directory.

## Usage
Send a file (prompts for the path and an optional passkey, then prints the passkey to share):
```bash
java pear2pear.Pear server
```

Receive a file (prompts for the passkey):
```bash
java pear2pear.Pear client
```

Run your own relay (control port 9009, data port 9010):
```bash
java pear2pear.Pear relay
```

## Configuration
The relay address is currently hard-coded as the `host` constant in `src/pear2pear/Sender.java` and `Receiver.java`, pointing at the author's relay, which is usually not running. To use the tool, run your own relay and change that constant to its address.

## Limitations
- Maximum file size is 100 MB.
- Custom passkeys must be 8-64 characters (alphanumeric, `-` or `_`).
