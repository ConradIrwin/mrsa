package mrsa

// This file defines the primitive operations on mediated RSA partial keys.

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
)

// A PublicKey represents the public part of a mediated RSA key
type PublicKey rsa.PublicKey

// A PartialDecryptor is used to decrypt a fragment of a message.
type PartialDecryptor interface {
	PartialDecrypt(c *big.Int) (*big.Int, error)
}
// A PrivateKey consists of the PublicKey and a partial decryption exponent D.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

// SplitPrivateKey takes an existing rsa.PrivateKey and splits it into two mrsa.PrivateKeys.
// The value of D for the first key is chosen uniformly, and the value for D of the second key
// is thus fixed.
func SplitPrivateKey(k *rsa.PrivateKey) (*PrivateKey, *PrivateKey, error) {

	k1 := &PrivateKey{PublicKey: PublicKey(k.PublicKey)}
	k2 := &PrivateKey{PublicKey: PublicKey(k.PublicKey)}

	err := k.Validate()

	if err != nil {
		return nil, nil, err
	}

	k1.D, err = rand.Int(rand.Reader, k.D)

	if err != nil {
		return nil, nil, err
	}

	k2.D = new(big.Int).Sub(k.D, k1.D)

	return k1, k2, nil
}

// encrypt performs RSA encryption on a message. Taken from the rsa package.
func (publ *PublicKey) encrypt(m *big.Int) *big.Int {
	e := big.NewInt(int64(publ.E))
	c := new(big.Int).Exp(m, e, publ.N)
	return c
}

// finalizeDecrypt takes the output of many PartialDecryptors with the same
// PublicKey and calculates the original plaintext message.
func (publ *PublicKey) finalizeDecrypt(ms ...*big.Int) *big.Int {
	m := big.NewInt(1)
	for _, p := range(ms) {
		m.Mul(m, p)
		m.Mod(m, publ.N)
	}
	return m
}
// PartialDecrypt takes a ciphertext c and computes a partial decryption.
// The output of this must be passed through PublicKey.finalizeDecrypt
// in order to be used.
func (priv *PrivateKey) PartialDecrypt(c *big.Int) (*big.Int, error) {
	m := new(big.Int).Exp(c, priv.D, priv.N)
	return m, nil
}
