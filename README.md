# True Cross-Platform ARJ
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://github.com/pedroalbanese/arj/blob/master/LICENSE.md) 
[![GoDoc](https://godoc.org/github.com/pedroalbanese/arj?status.png)](http://godoc.org/github.com/pedroalbanese/arj)
[![GitHub downloads](https://img.shields.io/github/downloads/pedroalbanese/arj/total.svg?logo=github&logoColor=white)](https://github.com/pedroalbanese/arj/releases)
[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/pedroalbanese/arj)](https://golang.org)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/pedroalbanese/arj)](https://github.com/pedroalbanese/arj/releases)

A modern, portable ARJ implementation in Go. Method 4 compression, method 0/4 decompression, Kuznyechik encryption (GOST R 34.12-2015) with Streebog-256 IV derivation. No external binaries.

## Features

| Component | Original ARJ | This project |
|---|---|---|
| Compression | Methods 0–4 | Method 4 (LZ77/LZSS) |
| Decompression | Methods 0–4 | Methods 0 (stored) and 4 |
| Encryption | GOST 28147-89 (obsolete) | Kuznyechik (GOST R 34.12-2015) |
| IV derivation | 8-byte modifier | Streebog-256(modifier) → 16 bytes |
| Integrity | CRC32 | CRC32 (kept) |
| Platforms | DOS, Windows, Linux (inconsistent) | Linux, macOS, Windows (consistent) |

## Installation

```bash
git clone https://github.com/pedroalbanese/arj.git
cd arj
go mod tidy
go build -ldflags=-s -o arj .
``` 


## License

This project is licensed under the ISC License.

#### Copyright (c) 2020-2026 Pedro F. Albanese - ALBANESE Research Lab.  
Todos os direitos de propriedade intelectual sobre este software pertencem ao autore, Pedro F. Albanese. Vide Lei 9.610/98, Art. 7º, inciso XII.
