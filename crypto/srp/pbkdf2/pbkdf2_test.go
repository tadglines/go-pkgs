package pbkdf2

import (
	"crypto/sha256"
	"testing"
)

func TestNewPBKDF2(t *testing.T) {
	fn := NewPBKDF2(10000, sha256.New)

	key := fn([]byte("salt"), []byte("password"))
	if len(key) != 32 {
		t.Fatalf("Expected a key size of %d, got %d", 32, len(key))
	}
}
