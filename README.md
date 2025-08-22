# pear2pear (i like pears)

A simple passkey-based file transfer tool with E2EE (AES-GCM) (using my own VPS as a relay, very secure yes yes) written in Java. Inspired by the workflow of tools like [croc](https://github.com/schollz/croc) (hopefully as far away from a 1:1 copy as possible).

## Installation
```bash
git clone https://github.com/Tjabooo/pear2pear.git
cd pear2pear/src
```
This guide will assume you are in the `src` directory.

## Build
```bash
javac pear2pear/*.java
```

## Sending file (server role)
```bash
java pear2pear/Pear.java server
...follow instructions
```

## Receiving file (client role)
```bash
java pear2pear/Pear.java client
...follow instructions
```

## Notes
- If you can't connect to the relay server, it is not running. Sorry.