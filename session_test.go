package mrsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto"
	"testing"
)

func TestSessionSign(t *testing.T) {

	k, err := rsa.GenerateKey(rand.Reader, 512)

	if err != nil {
		t.Fatal(err)
	}

	buffer := sha1.Sum([]byte("Monkey!"))
	hashed := buffer[0:20]

	t.Log(hashed)

	k1, k2, err := SplitPrivateKey(k)

	if err != nil {
		t.Fatal(err)
	}

	session := Session{k1.PublicKey, []PartialDecryptor{k1,k2}}

	signature, err := session.SignPKCS1v15(crypto.SHA1, hashed)

	if err != nil {
		t.Fatal(err)
	}

	err = rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA1, hashed, signature)

	if err != nil {
		t.Fatal(err)
	}
}
