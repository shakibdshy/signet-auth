package signet_test

import (
	"testing"

	"github.com/shakibdshy/signet"
)

func TestVersion(t *testing.T) {
	if signet.Version == "" {
		t.Fatal("Version must not be empty")
	}
}
