package mrsa

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"math/big"
)

// This file implements the actual signing of messages.

// A Session is an object that contains enough PartialDecryptors to
// fully sign a message using PKCS1.
type Session struct {
	PublicKey
	Decryptors []PartialDecryptor
}

// decrypt performs a full RSA decryption using multiple PartialDecryptors
func (session *Session) decrypt(c *big.Int) (* big.Int, error) {

	var err error
	ms := make([]*big.Int, len(session.Decryptors))

	for i, d := range(session.Decryptors) {
		ms[i], err = d.PartialDecrypt(c)
		if err != nil {
			return nil, err
		}
	}
	m := session.finalizeDecrypt(ms...)

	// we don't trust our partial decryptors very much, so we must
	// verify that the resulting decryption is valid.
	c2 := session.encrypt(m)
	if c2.Cmp(c) != 0 {
		return nil, errors.New("mrsa: decryption used a wrong RSA key")
	}

	return m, nil
}

// Most of this code is copied from http://golang.org/src/pkg/crypto/rsa/pkcs1v15.go

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// SignPKCS1v15 calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS#1 v1.5.
// Note that hashed must be the result of hashing the input message using the
// given hash function.
func (session *Session) SignPKCS1v15(hash crypto.Hash, hashed []byte) (s []byte, err error) {
	hashLen, prefix, err := pkcs1v15HashInfo(hash, len(hashed))
	if err != nil {
		return
	}

	tLen := len(prefix) + hashLen
	k := (session.N.BitLen() + 7) / 8
	if k < tLen+11 {
		return nil, rsa.ErrMessageTooLong
	}

	// EM = 0x00 || 0x01 || PS || 0x00 || T
	em := make([]byte, k)
	em[1] = 1
	for i := 2; i < k-tLen-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-tLen:k-hashLen], prefix)
	copy(em[k-hashLen:k], hashed)

	m := new(big.Int).SetBytes(em)
	c, err := session.decrypt(m)
	if err != nil {
		return
	}

	copyWithLeftPad(em, c.Bytes())
	s = em
	return
}

func pkcs1v15HashInfo(hash crypto.Hash, inLen int) (hashLen int, prefix []byte, err error) {
	hashLen = hash.Size()
	if inLen != hashLen {
		return 0, nil, errors.New("mrsa: input must be hashed message")
	}
	prefix, ok := hashPrefixes[hash]
	if !ok {
		return 0, nil, errors.New("mrsa: unsupported hash function")
	}
	return
}

// copyWithLeftPad copies src to the end of dest, padding with zero bytes as
// needed.
func copyWithLeftPad(dest, src []byte) {
	numPaddingBytes := len(dest) - len(src)
	for i := 0; i < numPaddingBytes; i++ {
		dest[i] = 0
	}
	copy(dest[numPaddingBytes:], src)
}

var hashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}
