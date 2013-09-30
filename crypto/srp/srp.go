// Copyright

// Package srp provides an implementation of SRP-6a as detailed
// at: http://srp.stanford.edu/design.html
package srp

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"hash"
	"io"
	"math/big"
)

const (
	DefaultSaltLength = 20
	DefaultABSize     = 32 * 8
)

// SRP contains values that must be the the same for both the client and server.
// SaltLength and ABSize are defaulted by NewSRP but can be changed after an SRP
// instance is created.
// Instances of SRP are safe for concurrent use.
type SRP struct {
	SaltLength int  // The size of the salt in bytes
	ABSize     uint // The size of a and b in bits
	HashFunc   func() hash.Hash
	Group      *SRPGroup
	_k         *big.Int
}

// ClientSession represents the client side of an SRP authentication session.
// ClientSession instances cannot be reused.
// Instances of ClientSession are NOT safe for concurrent use.
type ClientSession struct {
	SRP      *SRP
	username []byte
	salt     []byte
	password []byte
	_a       *big.Int
	_A       *big.Int
	_B       *big.Int
	_u       *big.Int
	key      []byte
	_M       []byte
}

// ServerSession represents the client side of an SRP authentication session.
// ServerSession instances cannot be reused.
// Instances of ServerSession are NOT safe for concurrent use.
type ServerSession struct {
	SRP      *SRP
	username []byte
	salt     []byte
	verifier []byte
	_v       *big.Int
	_b       *big.Int
	_A       *big.Int
	_B       *big.Int
	_u       *big.Int
	key      []byte
}

// NewSRP creates a new SRP context that will use the specified group and hash
// The set of supported groups are:
// 		rfc5054.1024
//		rfc5054.1536
//		rfc5054.2048
//		rfc5054.3072
//		rfc5054.4096
//		rfc5054.6144
//		rfc5054.8192
// 		stanford.1024
//		stanford.1536
//		stanford.2048
//		stanford.3072
//		stanford.4096
//		stanford.6144
//		stanford.8192
// The rfc5054 groups are from RFC5054
// The stanford groups where extracted from the stanford patch to OpenSSL.
func NewSRP(group string, h func() hash.Hash) (*SRP, error) {
	srp := new(SRP)
	srp.SaltLength = DefaultSaltLength
	srp.ABSize = DefaultABSize
	srp.HashFunc = h
	grp, ok := srp_groups[group]
	if !ok {
		return nil, fmt.Errorf("Invalid Group: %s", group)
	}
	srp.Group = grp

	srp.compute_k()

	return srp, nil
}

// ComputeVerifier generates a random salt and computes the verifier value that
// is associated with the user on the server.
func (s *SRP) ComputeVerifier(password []byte) (salt []byte, verifier []byte, err error) {
	//  x = H(s, p)               (s is chosen randomly)
	salt = make([]byte, s.SaltLength)
	n, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, nil, err
	}
	if n != len(salt) {
		return nil, nil, fmt.Errorf("Expected %d random bytes but only got %d bytes", s.SaltLength, n)
	}
	h := s.HashFunc()
	h.Write(salt)
	h.Write(password)

	//  v = g^x                   (computes password verifier)
	x := big.NewInt(0).SetBytes(h.Sum(nil))
	v := big.NewInt(0).Exp(s.Group.Generator, x, s.Group.Prime)

	return salt, v.Bytes(), nil
}

// NewClientSession creates a new ClientSession.
func (s *SRP) NewClientSession(username, password []byte) *ClientSession {
	cs := new(ClientSession)
	cs.SRP = s
	cs.username = username
	cs.password = password
	cs._a = s.gen_rand_ab()

	// g^a
	cs._A = big.NewInt(0).Exp(cs.SRP.Group.Generator, cs._a, cs.SRP.Group.Prime)
	return cs
}

// NewServerSession creates a new ServerSession.
func (s *SRP) NewServerSession(username, salt, verifier []byte) *ServerSession {
	ss := new(ServerSession)
	ss.SRP = s
	ss.username = username
	ss.salt = salt
	ss.verifier = verifier
	ss._b = s.gen_rand_ab()
	ss._v = big.NewInt(0).SetBytes(verifier)

	// kv + g^b
	ss._B = big.NewInt(0).Mul(ss.SRP._k, ss._v)
	ss._B.Add(ss._B, big.NewInt(0).Exp(ss.SRP.Group.Generator, ss._b, ss.SRP.Group.Prime))
	return ss
}

// GetA returns the bytes of the A value that need to be given to the server.
func (cs *ClientSession) GetA() []byte {
	return cs._A.Bytes()
}

// SetB sets the value of B that was returned by the server
func (cs *ClientSession) setB(B []byte) error {
	cs._B = big.NewInt(0).SetBytes(B)
	zero := big.NewInt(0)
	BN := big.NewInt(0).Mod(cs._B, cs.SRP.Group.Prime)
	if BN.Cmp(zero) == 0 {
		return fmt.Errorf("B%%N == 0")
	}
	h := cs.SRP.HashFunc()
	// u = H(A, B)
	h.Write(cs._A.Bytes())
	h.Write(cs._B.Bytes())
	cs._u = big.NewInt(0).SetBytes(h.Sum(nil))
	if cs._u.Cmp(zero) == 0 {
		return fmt.Errorf("H(A, B) == 0")
	}
	return nil
}

// ComputeKey computes the session key given the salt and the value of B.
func (cs *ClientSession) ComputeKey(salt, B []byte) ([]byte, error) {
	cs.salt = salt

	err := cs.setB(B)
	if err != nil {
		return nil, err
	}

	h := cs.SRP.HashFunc()
	// u = H(A, B)
	h.Write(cs._A.Bytes())
	h.Write(cs._B.Bytes())
	cs._u = big.NewInt(0).SetBytes(h.Sum(nil))
	h.Reset()

	// x = H(s, p)                 (user enters password)
	h.Write(cs.salt)
	h.Write(cs.password)
	x := big.NewInt(0).SetBytes(h.Sum(nil))
	h.Reset()

	// S = (B - kg^x) ^ (a + ux)   (computes session key)
	// t1 = g^x
	t1 := big.NewInt(0).Exp(cs.SRP.Group.Generator, x, cs.SRP.Group.Prime)
	// t1 = kg^x
	t1.Mul(cs.SRP._k, t1).Mod(t1, cs.SRP.Group.Prime)
	// t1 = B - kg^x
	t1.Sub(cs._B, t1).Mod(t1, cs.SRP.Group.Prime)
	// t2 = ux
	t2 := big.NewInt(0).Mul(cs._u, x)
	t2.Mod(t2, cs.SRP.Group.Prime)
	// t2 = a + ux
	t2.Add(cs._a, t2).Mod(t2, cs.SRP.Group.Prime)
	// t1 = (B - kg^x) ^ (a + ux)
	t1.Exp(t1, t2, cs.SRP.Group.Prime)
	// K = H(S)
	cs.key = h.Sum(t1.Bytes())

	return cs.key, nil
}

// GetKey returns the previously computed key
func (cs *ClientSession) GetKey() []byte {
	return cs.key
}

func computeClientAutneticator(h hash.Hash, grp *SRPGroup, username, salt, A, B, K []byte) []byte {
	//M = H(H(N) xor H(g), H(I), s, A, B, K)
	hn := big.NewInt(0).SetBytes(h.Sum(grp.Prime.Bytes()))
	h.Reset()
	hg := big.NewInt(0).SetBytes(h.Sum(grp.Generator.Bytes()))
	h.Reset()
	hi := h.Sum(username)
	h.Reset()
	hn.Xor(hn, hg)
	h.Write(hn.Bytes())
	h.Write(hi)
	h.Write(salt)
	h.Write(A)
	h.Write(B)
	h.Write(K)
	return h.Sum(nil)
}

func computeServerAuthenticator(h hash.Hash, A, M, K []byte) []byte {
	h.Write(A)
	h.Write(M)
	h.Write(K)
	return h.Sum(nil)
}

// ComputeAuthenticator computes an authenticator that is to be passed to the
// server for validation
func (cs *ClientSession) ComputeAuthenticator() []byte {
	h := cs.SRP.HashFunc()
	cs._M = computeClientAutneticator(h, cs.SRP.Group, cs.username, cs.salt, cs._A.Bytes(), cs._B.Bytes(), cs.key)
	return cs._M
}

// VerifyServerAuthenticator returns true if the authenticator returned by the
// server is valid
func (cs *ClientSession) VerifyServerAuthenticator(sauth []byte) bool {
	sa := computeServerAuthenticator(cs.SRP.HashFunc(), cs._A.Bytes(), cs._M, cs.key)
	return subtle.ConstantTimeCompare(sa, sauth) == 0
}

// Return the bytes for the value of B.
func (ss *ServerSession) GetB() []byte {
	return ss._B.Bytes()
}

func (ss *ServerSession) setA(A []byte) error {
	ss._A = big.NewInt(0).SetBytes(A)
	zero := big.NewInt(0)
	AN := big.NewInt(0).Mod(ss._A, ss.SRP.Group.Prime)
	if AN.Cmp(zero) == 0 {
		return fmt.Errorf("A%%N == 0")
	}
	h := ss.SRP.HashFunc()
	// u = H(A, B)
	h.Write(ss._A.Bytes())
	h.Write(ss._B.Bytes())
	ss._u = big.NewInt(0).SetBytes(h.Sum(nil))
	if ss._u.Cmp(zero) == 0 {
		return fmt.Errorf("H(A, B) == 0")
	}
	return nil
}

// ComputeKey computes the session key given the value of A.
func (ss *ServerSession) ComputeKey(A []byte) ([]byte, error) {
	err := ss.setA(A)
	if err != nil {
		return nil, err
	}

	// S = (Av^u) ^ b              (computes session key)
	S := big.NewInt(0).Exp(ss._v, ss._u, ss.SRP.Group.Prime)
	S.Mul(ss._A, S).Mod(S, ss.SRP.Group.Prime)
	S.Exp(S, ss._b, ss.SRP.Group.Prime)
	// K = H(S)
	h := ss.SRP.HashFunc()
	return h.Sum(S.Bytes()), nil
}

// ComputeAuthenticator computes an authenticator to be passed to the client.
func (ss *ServerSession) ComputeAuthenticator(cauth []byte) []byte {
	return computeServerAuthenticator(ss.SRP.HashFunc(), ss._A.Bytes(), cauth, ss.key)
}

// VerifyClientAuthenticator returns true if the client authenticator
// is valid.
func (ss *ServerSession) VerifyClientAuthenticator(cauth []byte) bool {
	M := computeClientAutneticator(ss.SRP.HashFunc(), ss.SRP.Group, ss.username, ss.salt, ss._A.Bytes(), ss._B.Bytes(), ss.key)
	return subtle.ConstantTimeCompare(M, cauth) == 0
}

func (s *SRP) compute_k() {
	h := s.HashFunc()
	h.Write(s.Group.Prime.Bytes())
	h.Write(s.Group.Generator.Bytes())
	s._k = big.NewInt(0).SetBytes(h.Sum(nil))
}

func (s *SRP) gen_rand_ab() *big.Int {
	max := big.NewInt(0).Lsh(big.NewInt(1), s.ABSize)
	r, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(err)
	}
	return r
}
