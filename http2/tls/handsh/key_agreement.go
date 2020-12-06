package handsh

import (
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"errors"
)

var (
	errClientKeyExchange = errors.New("tls: invalid ClientKeyExchange message")
	errServerKeyExchange = errors.New("tls: invalid ServerKeyExchange message")
)

func hashForServerKeyExchange(sigType uint8, hashFunc crypto.Hash, version uint16, slices ...[]byte) []byte {
	if sigType == signatureEd25519 {
		var signed []byte
		for _, slice := range slices {
			signed = append(signed, slice...)
		}
		return signed
	}
	if version >= tls.VersionTLS12 {
		h := hashFunc.New()
		for _, slice := range slices {
			h.Write(slice)
		}
		digest := h.Sum(nil)
		return digest
	}
	if sigType == signatureECDSA {
		return sha1Hash(slices)
	}
	return md5SHA1Hash(slices)
}

// sha1Hash calculates a SHA1 hash over the given byte slices.
func sha1Hash(slices [][]byte) []byte {
	hsha1 := sha1.New()
	for _, slice := range slices {
		hsha1.Write(slice)
	}
	return hsha1.Sum(nil)
}

// md5SHA1Hash implements TLS 1.0's hybrid hash function which consists of the
// concatenation of an MD5 and SHA1 hash.
func md5SHA1Hash(slices [][]byte) []byte {
	md5sha1 := make([]byte, md5.Size+sha1.Size)
	hmd5 := md5.New()
	for _, slice := range slices {
		hmd5.Write(slice)
	}
	copy(md5sha1, hmd5.Sum(nil))
	copy(md5sha1[md5.Size:], sha1Hash(slices))
	return md5sha1
}

// ecdheKeyAgreement
type ecdheKeyAgreement struct {
	version uint16
	isRSA   bool
	params  ecdheParameters

	// ckx and preMasterSecret are generated in processServerKeyExchange
	// and returned in generateClientKeyExchange.
	ckx             *clientKeyExchangeMsg
	preMasterSecret []byte
}

// 依据client逻辑解析，故忽略此内部逻辑
func (ka *ecdheKeyAgreement) generateServerKeyExchange(config *tls.Config, cert *tls.Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	return nil, nil
}

func (ka *ecdheKeyAgreement) processServerKeyExchange(config *tls.Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	if len(skx.key) < 4 {
		return errServerKeyExchange
	}
	if skx.key[0] != 3 { // named curve
		return errors.New("tls: server selected unsupported curve")
	}
	curveID := tls.CurveID(skx.key[1])<<8 | tls.CurveID(skx.key[2])

	publicLen := int(skx.key[3])
	if publicLen+4 > len(skx.key) {
		return errServerKeyExchange
	}
	serverECDHEParams := skx.key[:4+publicLen]
	publicKey := serverECDHEParams[4:]

	sig := skx.key[4+publicLen:]
	if len(sig) < 2 {
		return errServerKeyExchange
	}

	if _, ok := curveForCurveID(curveID); curveID != tls.X25519 && !ok {
		return errors.New("tls: server selected unsupported curve")
	}

	// 这里改变生成随机数据的逻辑
	params, err := generateECDHEParameters(crand(config), curveID)
	if err != nil {
		return err
	}
	ka.params = params

	ka.preMasterSecret = params.SharedKey(publicKey)
	if ka.preMasterSecret == nil {
		return errServerKeyExchange
	}

	ourPublicKey := params.PublicKey()
	ka.ckx = new(clientKeyExchangeMsg)
	ka.ckx.ciphertext = make([]byte, 1+len(ourPublicKey))
	ka.ckx.ciphertext[0] = byte(len(ourPublicKey))
	copy(ka.ckx.ciphertext[1:], ourPublicKey)

	var sigType uint8
	var sigHash crypto.Hash
	if ka.version >= tls.VersionTLS12 {
		signatureAlgorithm := tls.SignatureScheme(sig[0])<<8 | tls.SignatureScheme(sig[1])
		sig = sig[2:]
		if len(sig) < 2 {
			return errServerKeyExchange
		}

		if !isSupportedSignatureAlgorithm(signatureAlgorithm, clientHello.supportedSignatureAlgorithms) {
			return errors.New("tls: certificate used with invalid signature algorithm")
		}
		sigType, sigHash, err = typeAndHashFromSignatureScheme(signatureAlgorithm)
		if err != nil {
			return err
		}
	} else {
		sigType, sigHash, err = legacyTypeAndHashFromPublicKey(cert.PublicKey)
		if err != nil {
			return err
		}
	}
	if (sigType == signaturePKCS1v15 || sigType == signatureRSAPSS) != ka.isRSA {
		return errServerKeyExchange
	}

	sigLen := int(sig[0])<<8 | int(sig[1])
	if sigLen+2 != len(sig) {
		return errServerKeyExchange
	}
	sig = sig[2:]

	signed := hashForServerKeyExchange(sigType, sigHash, ka.version, clientHello.random, serverHello.random, serverECDHEParams)
	if err := verifyHandshakeSignature(sigType, cert.PublicKey, sigHash, signed, sig); err != nil {
		return errors.New("tls: invalid signature by the server certificate: " + err.Error())
	}
	return nil
}

// 依据client逻辑解析，故忽略此内部逻辑
func (ka *ecdheKeyAgreement) processClientKeyExchange(config *tls.Config, cert *tls.Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	return nil, nil
}

func (ka *ecdheKeyAgreement) generateClientKeyExchange(config *tls.Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.ckx == nil {
		return nil, nil, errors.New("tls: missing ServerKeyExchange message")
	}

	return ka.preMasterSecret, ka.ckx, nil
}
