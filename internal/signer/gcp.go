package signer

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

// GCPSigner a GCP asymetric crypto signer
type GCPSigner struct {
	crypto.Signer
	ctx    context.Context
	client *kms.KeyManagementClient
	key    string
}

// NewGCPSSigner return a new instsance of NewGCPSSigner
func NewGCPSSigner(key string) *GCPSigner {
	ctx := context.Background()
	c, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		panic(err)
	}

	return &GCPSigner{
		ctx:    ctx,
		client: c,
		key:    key,
	}
}

// Public returns the public key from KMS
func (s *GCPSigner) Public() crypto.PublicKey {
	response, err := s.client.GetPublicKey(s.ctx, &kmspb.GetPublicKeyRequest{
		Name: s.key,
	})
	if err != nil {
		log.Print(err.Error())
		return nil
	}
	switch response.GetAlgorithm() {
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512:
		// awesome
	default:
		log.Print("crypto key has the wrong algorithm, must be rsa with PKCS1 padding")
		return nil
	}

	pubPem := response.GetPem()
	// pubAlg := response.GetAlgorithm()
	pemBlock, _ := pem.Decode([]byte(pubPem))

	publicKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		log.Print(err.Error())
		return nil
	}

	return publicKey
}

// Sign a digest with the private key in KMS
func (s *GCPSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var dig *kmspb.Digest = &kmspb.Digest{}
	switch opts {
	case crypto.SHA256:
		dig.Digest = &kmspb.Digest_Sha256{
			Sha256: digest,
		}
	case crypto.SHA384:
		dig.Digest = &kmspb.Digest_Sha384{
			Sha384: digest,
		}
	case crypto.SHA512:
		dig.Digest = &kmspb.Digest_Sha512{
			Sha512: digest,
		}
	}

	response, err := s.client.AsymmetricSign(s.ctx, &kmspb.AsymmetricSignRequest{
		Name:   s.key,
		Digest: dig,
	})
	if err != nil {
		return nil, err
	}
	sig := response.GetSignature()
	pubKey := s.Public()
	rKey := pubKey.(*rsa.PublicKey)
	err = rsa.VerifyPKCS1v15(rKey, crypto.SHA256, digest, sig)
	if err != nil {
		return nil, err
	}
	return sig, nil
}
