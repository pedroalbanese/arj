# True Cross-Platform ARJ
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/arj/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/arj?status.png)](http://godoc.org/github.com/pedroalbanese/arj)
[![GitHub downloads](https://img.shields.io/github/downloads/pedroalbanese/arj/total.svg?logo=github&logoColor=white)](https://github.com/pedroalbanese/arj/releases)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/pedroalbanese/arj)](https://golang.org)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/arj)](https://github.com/pedroalbanese/arj/releases)

A modern, portable ARJ implementation in Go. Method 4 compression, method 0–4 decompression, Kuznyechik encryption (GOST R 34.12-2015) with Streebog-256 IV derivation. No external binaries.

## Features

| Component | Original ARJ | This project |
|---|---|---|
| Compression | Methods 0–4 | Method 4 (LZ77/LZSS) |
| Decompression | Methods 0–4 | Methods 0–4 (kept) |
| Encryption | GOST 28147-89 (obsolete) | Kuznyechik (GOST R 34.12-2015) |
| IV derivation | 8-byte modifier | Streebog-256(modifier) → 16 bytes |
| Integrity | CRC32 | CRC32 (kept) |
| Platforms | DOS, Windows, Linux (inconsistent) | Linux, macOS, Windows (consistent) |

## Usage
``` 
ARJ Evolved — The ARJ format, with a modern encryption layer.

Usage:     arj <command> [-<sw> [-<sw>...]] <archive_name> [<file_names>...]
Examples:  arj a -gsecret archive, arj x -gsecret archive, arj l archive
           arj a -v1440 archive.arj file1 file2

<Commands>
  a: Add files to archive               d: Delete files from archive
  l: List contents of archive           t: Test integrity of archive
  x: eXtract files with full pathname   -h: Show this help

<Switches>
  g: Garble with password (Kuznyechik)  y: assume Yes on all queries
  v: create multi-Volume archive in KB  u: Update files (new and newer)

Notes:
  - Compression uses method 4 (LZ77/LZSS).
  - Decompression accepts methods 0–4.
  - Encryption uses Kuznyechik (GOST R 34.12-2015) in CFB Mode.
  - Key derivation uses PBKDF2-Streebog-256 (GOST R 34.11-2012).
  - Authentication uses HMAC-Streebog-256 (GOST R 34.11-2012).
  - CRC32 is kept for header compatibility.
```

## Installation

```bash
git clone https://github.com/pedroalbanese/arj.git
cd arj
go mod tidy
go build -ldflags=-s -o arj .
``` 

## Contribute
**Use issues for everything**
- You can help and get help by:
  - Reporting doubts and questions
- You can contribute by:
  - Reporting issues
  - Suggesting new features or enhancements
  - Improve/fix documentation


## License

This project is licensed under the ISC License.
The original ARJ code (GOST 28147-89, method 4) is public domain (ARJ Software Russia).

#### Copyright (c) 2020-2026 Pedro F. Albanese - ALBANESE Research Lab.  
Todos os direitos de propriedade intelectual sobre este software pertencem ao autore, Pedro F. Albanese. Vide Lei 9.610/98, Art. 7º, inciso XII.
