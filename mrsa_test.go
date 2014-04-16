package mrsa

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
)

func TestSplit(t *testing.T) {

	k, err := rsa.GenerateKey(rand.Reader, 512)

	if err != nil {
		t.Fatal(err)
	}

	d1, d2, err := SplitPrivateKey(k)

	if err != nil {
		t.Fatal(err)
	}

	sum := new(big.Int).Add(d1.D, d2.D)

	if sum.Cmp(k.D) != 0 {
		t.Fatal("split was not total")
	}
}

func TestDecrypt(t *testing.T) {

	k, err := rsa.GenerateKey(rand.Reader, 512)

	if err != nil {
		t.Fatal(err)
	}

	d1, d2, err := SplitPrivateKey(k)

	if err != nil {
		t.Fatal(err)
	}

	m, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil))

	if err != nil {
		t.Fatal(err)
	}

	c := d1.PublicKey.encrypt(m)

	m1, err := d1.PartialDecrypt(c)

	if err != nil {
		t.Fatal(err)
	}

	m2, err := d2.PartialDecrypt(c)

	if err != nil {
		t.Fatal(err)
	}

	d := d1.PublicKey.finalizeDecrypt(m1, m2)

	if d.Cmp(m) != 0 {
		t.Fatal("decrypt didn't work")
	}
}
