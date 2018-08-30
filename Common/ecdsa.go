package main

import (
	"crypto/ecdsa"
	"encoding/asn1"
	"math/big"

	"github.com/hyperledger/fabric/core/chaincode/shim/crypto"
)

type x509ECDSASignatureVerifierImpl struct {
}

// ECDSASignature represents an ECDSA signature
type ECDSASignature struct {
	R, S *big.Int
}

func (sv *x509ECDSASignatureVerifierImpl) Verify(certificate, signature, message []byte) (bool, error) {
	// Interpret vk as an x509 certificate
	cert, err := derToX509Certificate(certificate)
	if err != nil {
		return false, err
	}

	// TODO: verify certificate

	// Interpret signature as an ECDSA signature
	vk := cert.PublicKey.(*ecdsa.PublicKey)

	return sv.verifyImpl(vk, signature, message)
}

func (sv *x509ECDSASignatureVerifierImpl) verifyImpl(vk *ecdsa.PublicKey, signature, message []byte) (bool, error) {
	ecdsaSignature := new(ECDSASignature)
	_, err := asn1.Unmarshal(signature, ecdsaSignature)
	if err != nil {
		return false, err
	}

	h, err := computeHash(message, vk.Params().BitSize)
	if err != nil {
		return false, err
	}

	return ecdsa.Verify(vk, h, ecdsaSignature.R, ecdsaSignature.S), nil
}

func NewX509ECDSASignatureVerifier() crypto.SignatureVerifier {
	return &x509ECDSASignatureVerifierImpl{}
}