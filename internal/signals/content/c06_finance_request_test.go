package content

import "testing"

func TestValidKZIdentifier(t *testing.T) {
	valid := "000000000000"
	if validKZIdentifier(valid) {
		t.Fatal("all-zero identifier must not be accepted")
	}
	// 970740000015 is a checksum-valid synthetic test identifier.
	if !validKZIdentifier("970740000015") {
		t.Fatal("expected valid KZ identifier")
	}
	if validKZIdentifier("970740000016") {
		t.Fatal("changed control digit must be rejected")
	}
}
