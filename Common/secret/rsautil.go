package main

import (
	"fmt"
	"github.com/hyperledger/fabric/core/crypto/primitives"
	"github.com/hyperledger/fabric/core/chaincode/shim/crypto/ecdsa"
)

func main() {

	// Create a signature
	primitives.SetSecurityLevel("SHA3", 256)

	cert, key, err := primitives.NewSelfSignedCert()
	if err != nil {
		fmt.Println(err)
	}

	message := []byte("Hello World!")
	signature, err := primitives.ECDSASign(key, message)
	if err != nil {
		fmt.Println(err)
	}

	// Instantiate a new SignatureVerifier
	sv := ecdsa.NewX509ECDSASignatureVerifier()

	// Verify the signature
	ok, err := sv.Verify(cert, signature, message)
	if err != nil {
		fmt.Println(err)
	}
	if !ok {
		fmt.Println("Signature does not verify")
	}

}
