package scrypt

import (
	"testing"
)

func TestNewScrypt(t *testing.T) {
	fn, err := NewScrypt(16384, 8, 1)
	if err != nil {
		t.Fatal(err)
	}

	key := fn([]byte("salt"), []byte("password"))
	if len(key) != 32 {
		t.Fatalf("Expected a key size of %d, got %d", 32, len(key))
	}
}
