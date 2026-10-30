package main

import (
	"crypto/cipher"
	"encoding/binary"
)

type ARJCrypt struct {
	block     cipher.Block
	backCode  [16]byte
	lastBytes int
}

// Init initializes the cipher with a 32-byte encryption key and a
// 4-byte IV (stored in the "reserved" field of the local header).
//
// The IV is no longer derived from the timestamp: it is a random
// per-file value, so two files with the same timestamp but different
// IVs produce different keystreams.
//
// The 4-byte IV is expanded to the 16-byte backCode via Streebog-256.
func (c *ARJCrypt) Init(encKey []byte, iv uint32) {
	c.block = newKuznyechikCipher(encKey)

	ivBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ivBytes, iv)

	hash := streebogSum256(ivBytes)
	copy(c.backCode[:], hash[:16])

	c.lastBytes = 0
}

func (c *ARJCrypt) Encode(data []byte) {
	n := len(data)
	full := n / KuznyechikBlockSize
	rem := n % KuznyechikBlockSize

	for i := 0; i < full; i++ {
		ks := make([]byte, KuznyechikBlockSize)
		c.block.Encrypt(ks, c.backCode[:])

		for j := 0; j < KuznyechikBlockSize; j++ {
			data[i*KuznyechikBlockSize+j] ^= ks[j]
		}
		copy(c.backCode[:], data[i*KuznyechikBlockSize:i*KuznyechikBlockSize+KuznyechikBlockSize])
	}

	if rem > 0 {
		c.encodePartial(data[full*KuznyechikBlockSize:])
	}
}

func (c *ARJCrypt) encodePartial(data []byte) {
	for i := 0; i < len(data); i++ {
		if c.lastBytes == 0 {
			ks := make([]byte, KuznyechikBlockSize)
			c.block.Encrypt(ks, c.backCode[:])
			copy(c.backCode[:], ks)
		}
		data[i] ^= c.backCode[c.lastBytes]
		c.backCode[c.lastBytes] = data[i]
		c.lastBytes = (c.lastBytes + 1) % KuznyechikBlockSize
	}
}

func (c *ARJCrypt) Decode(data []byte) {
	n := len(data)
	full := n / KuznyechikBlockSize
	rem := n % KuznyechikBlockSize

	for i := 0; i < full; i++ {
		ks := make([]byte, KuznyechikBlockSize)
		c.block.Encrypt(ks, c.backCode[:])

		ct := make([]byte, KuznyechikBlockSize)
		copy(ct, data[i*KuznyechikBlockSize:i*KuznyechikBlockSize+KuznyechikBlockSize])

		for j := 0; j < KuznyechikBlockSize; j++ {
			data[i*KuznyechikBlockSize+j] ^= ks[j]
		}
		copy(c.backCode[:], ct)
	}

	if rem > 0 {
		c.decodePartial(data[full*KuznyechikBlockSize:])
	}
}

func (c *ARJCrypt) decodePartial(data []byte) {
	for i := 0; i < len(data); i++ {
		if c.lastBytes == 0 {
			ks := make([]byte, KuznyechikBlockSize)
			c.block.Encrypt(ks, c.backCode[:])
			copy(c.backCode[:], ks)
		}
		enc := data[i]
		data[i] = enc ^ c.backCode[c.lastBytes]
		c.backCode[c.lastBytes] = enc
		c.lastBytes = (c.lastBytes + 1) % KuznyechikBlockSize
	}
}
