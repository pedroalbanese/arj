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

func (c *ARJCrypt) Init(password string, modifier [2]uint32) {
	// Chave de 32 bytes (zero-padded)
	key := make([]byte, 32)
	copy(key, []byte(password))

	// Cria o cifrador Kuznyechik (não retorna error)
	c.block = newKuznyechikCipher(key)

	// IV de 16 bytes derivado do modifier via Streebog-256
	modBytes := make([]byte, 8)
	binary.LittleEndian.PutUint32(modBytes[0:4], modifier[0])
	binary.LittleEndian.PutUint32(modBytes[4:8], modifier[1])

	hash := streebogSum256(modBytes)
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
