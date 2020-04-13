package sw

import (
	"crypto/rand"

	"github.com/michain-org/hspeed-sdk-go/gm/gmsm/sm2"
	"github.com/michain-org/hspeed-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
)

func signSM2(k *sm2.PrivateKey, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return k.Sign(rand.Reader, digest, opts)
}

func verifySM2(k *sm2.PublicKey, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	//r, s, err := utils.UnmarshalSM2Signature(signature)
	//if err != nil {
	//	return false, fmt.Errorf("Failed unmashalling signature [%s]", err)
	//}
	//
	//lowS, err := utils.IsSM2LowS(k, s)
	//if err != nil {
	//	return false, err
	//}
	//
	//if !lowS {
	//	return false, fmt.Errorf("Invalid S. Must be smaller than half the order [%s][%s].", s, utils.GetCurveHalfOrdersAt(k.Curve))
	//}

	return k.Verify(digest, signature), nil
}

type sm2Signer struct{}

func (s *sm2Signer) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return signSM2(k.(*sm2PrivateKey).privKey, digest, opts)
}

type sm2PrivateKeyVerifier struct{}

func (v *sm2PrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifySM2(&(k.(*sm2PrivateKey).privKey.PublicKey), signature, digest, opts)
}

type sm2PublicKeyKeyVerifier struct{}

func (v *sm2PublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifySM2(k.(*sm2PublicKey).pubKey, signature, digest, opts)
}
