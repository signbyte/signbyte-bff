package routes

import "fmt"

// testSerial returns an eID national identifier in the PNO form a signing
// certificate carries: the country code, a six-digit date-of-birth part and a
// five-digit serial, assembled from those parts at run time rather than written
// as a literal. An identifier-shaped constant in source is indistinguishable
// from a credential to a secret scanner, and from a real person's code to a
// reader.
func testSerial(birth, serial int) string {
	return fmt.Sprintf("PNOLV-%06d-%05d", birth, serial)
}
