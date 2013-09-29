package srp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"
)

var groups []string = []string{"1024", "1536", "2048", "3072", "4096", "6144", "8192"}

var passwords []string = []string{
	"0",
	"a",
	"password",
	"This Is A Long Password",
	"This is a really long password a;lsdfkjauiwjenfasueifxl3847tq8374y(*&^JHG&*^$.kjbh()&*^KJG",
}

type hashFunc func() hash.Hash

var hashes []hashFunc = []hashFunc{
	sha1.New,
	sha256.New,
	sha512.New,
}

func testSRP(t *testing.T, group string, h func() hash.Hash, username, password []byte) {
	srp, _ := NewSRP(group, h)
	cs := srp.NewClientSession(username, password)
	salt, v, err := srp.ComputeVerifier(password)
	if err != nil {
		t.Fatal(err)
	}
	ss := srp.NewServerSession(username, salt, v)

	_, err = cs.ComputeKey(salt, ss.GetB())
	if err != nil {
		t.Fatal(err)
	}

	_, err = ss.ComputeKey(cs.GetA())
	if err != nil {
		t.Fatal(err)
	}

	cauth := cs.ComputeAuthenticator()
	if !ss.VerifyClientAuthenticator(cauth) {
		t.Fatal("Client Authenticator is not valid")
	}

	sauth := ss.ComputeAuthenticator(cauth)
	if !ss.VerifyClientAuthenticator(sauth) {
		t.Fatal("Server Authenticator is not valid")
	}
}

func TestSRPSimple(t *testing.T) {
	for _, g := range groups {
		for _, h := range hashes {
			for _, p := range passwords {
				testSRP(t, g, h, []byte("test"), []byte(p))
			}
		}
	}
}
