package tests

import (
	"testing"

	"github.com/shakibdshy/signet-auth"
)

func TestVersion(t *testing.T) {
	if signet.Version == "" {
		t.Fatal("Version must not be empty")
	}
}
