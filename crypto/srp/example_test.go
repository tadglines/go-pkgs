package srp

import (
	"crypto/sha256"
	"log"
)

func ExampleNewSRP() {
	username := []byte("example")
	password := []byte("3x@mp1e")

	srp, err := NewSRP("1024", sha256.New)
	if err != nil {
		log.Fatal(err)
	}

	cs := srp.NewClientSession(username, password)
	salt, v, err := srp.ComputeVerifier(password)
	if err != nil {
		log.Fatal(err)
	}

	ss := srp.NewServerSession(username, salt, v)

	ckey, err := cs.ComputeKey(salt, ss.GetB())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("The Client's computed session key is: %v\n", ckey)

	skey, err := ss.ComputeKey(cs.GetA())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("The Server's computed session key is: %v\n", skey)

	cauth := cs.ComputeAuthenticator()
	if !ss.VerifyClientAuthenticator(cauth) {
		log.Fatal("Client Authenticator is not valid")
	}
	sauth := ss.ComputeAuthenticator(cauth)
	if !ss.VerifyClientAuthenticator(sauth) {
		log.Fatal("Server Authenticator is not valid")
	}
}
