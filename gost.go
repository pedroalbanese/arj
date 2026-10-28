package main

// ===========================================================================
// Wrapper para a biblioteca pedroalbanese/gogost
// ===========================================================================

import (
	"crypto/cipher"
	"github.com/pedroalbanese/gogost/gost3412128"
	"github.com/pedroalbanese/gogost/gost34112012256"
)

const (
	KuznyechikBlockSize = gost3412128.BlockSize // 16 bytes
	KuznyechikKeySize   = gost3412128.KeySize   // 32 bytes
)

// newKuznyechikCipher cria um cifrador de bloco Kuznyechik.
// A função da gogost retorna apenas cipher.Block, sem erro.
func newKuznyechikCipher(key []byte) cipher.Block {
	return gost3412128.NewCipher(key)
}

// streebogSum256 calcula o hash Streebog-256 de um dado.
func streebogSum256(data []byte) []byte {
	h := gost34112012256.New()
	h.Write(data)
	return h.Sum(nil)
}
