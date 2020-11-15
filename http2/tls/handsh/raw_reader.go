package handsh

import (
	"bytes"
	"crypto/cipher"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"io"
	"net"
)

type aead interface {
	cipher.AEAD

	// explicitNonceLen returns the number of bytes of explicit nonce
	// included in each record. This is eight for older AEADs and
	// zero for modern ones.
	explicitNonceLen() int
}

type cbcMode interface {
	cipher.BlockMode
	SetIV([]byte)
}

type macFunction interface {
	// Size returns the length of the MAC.
	Size() int
	// MAC appends the MAC of (seq, header, data) to out. The extra data is fed
	// into the MAC after obtaining the result to normalize timing. The result
	// is only valid until the next invocation of MAC as the buffer is reused.
	MAC(seq, header, data, extra []byte) []byte
}

// 把数据读取为一个一个的msg
type rawReader struct {
	isClient bool

	version        uint16      // protocol version
	cipher         interface{} // cipher algorithm
	mac            macFunction
	seq            [8]byte  // 64-bit sequence number
	additionalData [13]byte // to avoid allocs; interface method args escape

	nextCipher interface{} // next encryption state
	nextMac    macFunction // next MAC algorithm

	trafficSecret []byte // current TLS 1.3 traffic secret
	rawData       bytes.Buffer

	logger KeyLog

	emit func(isClient bool, msg interface{}, err error)
}

// 交给指定reader读取数据
func (rr *rawReader) parse(data []byte) {
	// 补充数据
	rr.rawData.Write(data)
	var err error
	// 开始解析数据
	for {
		// 如果数据已经读取完毕，或者已经没有数据了，则暂停本次解析
		if rr.rawData.Len() == 0 || rr.rawData.Len() < recordHeaderLen {
			break
		}
		hdr := rr.rawData.Bytes()[:recordHeaderLen]
		typ := recordType(hdr[0])

		n := int(hdr[3])<<8 | int(hdr[4])
		if rr.version == tls.VersionTLS13 && n > maxCiphertextTLS13 || n > maxCiphertext {
			err = fmt.Errorf("oversized record received with length %d", n)
			break
		}
		// 如果数据长度还是不够，则继续等待数据进入buf
		if rr.rawData.Len() < recordHeaderLen+n {
			break
		}
		// 取出原始数据
		record := rr.rawData.Next(recordHeaderLen + n)
		rawData := make([]byte, len(record))
		copy(rawData, record)
		data, typ, e := rr.decrypt(record)
		if e != nil {
			err = e
			break
		}
		// other check
		if len(data) > maxPlaintext {
			err = alertRecordOverflow
			break
		}

		// Application Data messages are always protected.
		if rr.cipher == nil && typ == recordTypeApplicationData {
			err = alertUnexpectedMessage
			break
		}

		switch typ {
		default:
			err = alertUnexpectedMessage
		case recordTypeAlert:
			if len(data) != 2 {
				err = alertUnexpectedMessage
			} else if alert(data[1]) == alertCloseNotify {
				err = io.EOF
			} else if rr.version == tls.VersionTLS13 {
				err = &net.OpError{Op: "remote error", Err: alert(data[1])}
			}
			switch data[0] {
			case alertLevelError:
				err = &net.OpError{Op: "remote error", Err: alert(data[1])}
			default:
				err = alertUnexpectedMessage
			}

		case recordTypeChangeCipherSpec:
			if len(data) != 1 || data[0] != 1 {
				err = alertDecodeError
			}
			// 本次demo使用tls1.3,在tls1.3中会忽略change_cipher_spec records
			if rr.version == tls.VersionTLS13 {
				rr.logger.Info("ignore ChangeCipherSpec record")
				continue
			}
			// if err := rr.changeCipherSpec(); err != nil {
			// 	return err
			// }
			rr.logger.Info("you must impletes ChangeCipherSpec logic")
		case recordTypeApplicationData:
			// 打印用户传输的数据
			rr.logger.Info(fmt.Sprintf("read internet deliver content: %s", string(rawData)))
			rr.logger.Info(fmt.Sprintf("read application content: %s", string(data)))
		case recordTypeHandshake:
			// 处理解密后的握手数据
			if len(data) == 0 {
				err = alertUnexpectedMessage
				break
			}
			msg, e := rr.parseToMsg(data)
			rr.emitMsg(rr.isClient, msg, e)
			if e != nil {
				err = e
				break
			}
		}
	}
	if err != nil {
		// 数据有误需要清除
		rr.rawData.Reset()
		rr.logger.Err(err.Error())
	}
}

func (rr *rawReader) parseToMsg(b []byte) (interface{}, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("data format error")
	}
	n := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if n > 65536 { // maximum handshake we support (protocol max is 16 MB)
		return nil, fmt.Errorf("tls: handshake message of length %d bytes exceeds maximum of %d bytes", n, 65536)
	}
	var m handshakeMessage
	// b = append([]byte(nil), b...)
	switch b[0] {
	case typeHelloRequest:
		rr.logger.Info("read helloRequestMsg")
		m = new(helloRequestMsg)
	case typeClientHello:
		rr.logger.Info("read clientHelloMsg")
		m = new(clientHelloMsg)
	case typeServerHello:
		rr.logger.Info("read serverHelloMsg")
		m = new(serverHelloMsg)
	case typeNewSessionTicket:
		// TODO
	case typeCertificate:
		if rr.version == tls.VersionTLS13 {
			rr.logger.Info("read certificateMsgTLS13")
			m = new(certificateMsgTLS13)
		} else {
			rr.logger.Info("read certificateMsg")
			m = new(certificateMsg)
		}
	case typeCertificateRequest:
		if rr.version == tls.VersionTLS13 {
			rr.logger.Info("read certificateRequestMsgTLS13")
			m = new(certificateRequestMsgTLS13)
		} else {
			rr.logger.Info("read certificateRequestMsg")
			m = &certificateRequestMsg{
				hasSignatureAlgorithm: rr.version >= tls.VersionTLS12,
			}
		}
	case typeCertificateStatus:
		// TODO
	case typeServerKeyExchange:
		rr.logger.Info("read serverKeyExchangeMsg")
		m = new(serverKeyExchangeMsg)
	case typeServerHelloDone:
		rr.logger.Info("read serverHelloDoneMsg")
		m = new(serverHelloDoneMsg)
	case typeClientKeyExchange:
		rr.logger.Info("read clientKeyExchangeMsg")
		m = new(clientKeyExchangeMsg)
	case typeCertificateVerify:
		rr.logger.Info("read certificateVerifyMsg")
		m = &certificateVerifyMsg{
			hasSignatureAlgorithm: rr.version >= tls.VersionTLS12,
		}
	case typeFinished:
		rr.logger.Info("read finishedMsg")
		m = new(finishedMsg)
	case typeEncryptedExtensions:
		rr.logger.Info("read encryptedExtensionsMsg")
		m = new(encryptedExtensionsMsg)
	case typeEndOfEarlyData:
		// TODO
	case typeKeyUpdate:
		// TODO
	default:
		return nil, fmt.Errorf("unkonw handshake msg")
	}
	if m != nil && m.unmarshal(b) {
		return m, nil
	}
	return nil, fmt.Errorf("you need to new a msg to avoid error")
}

func (rr *rawReader) emitMsg(isClient bool, msg interface{}, err error) {
	if rr.emit == nil {
		return
	}
	rr.emit(isClient, msg, err)
}

func (rr *rawReader) decrypt(record []byte) ([]byte, recordType, error) {
	var plaintext []byte
	typ := recordType(record[0])
	payload := record[recordHeaderLen:]

	// In TLS 1.3, change_cipher_spec messages are to be ignored without being
	// decrypted. See RFC 8446, Appendix D.4.
	if rr.version == tls.VersionTLS13 && typ == recordTypeChangeCipherSpec {
		return payload, typ, nil
	}

	paddingGood := byte(255)
	paddingLen := 0

	explicitNonceLen := rr.explicitNonceLen()

	if rr.cipher != nil {
		switch c := rr.cipher.(type) {
		case cipher.Stream:
			c.XORKeyStream(payload, payload)
		case aead:
			if len(payload) < explicitNonceLen {
				return nil, 0, alertBadRecordMAC
			}
			nonce := payload[:explicitNonceLen]
			if len(nonce) == 0 {
				nonce = rr.seq[:]
			}
			payload = payload[explicitNonceLen:]

			additionalData := rr.additionalData[:]
			if rr.version == tls.VersionTLS13 {
				additionalData = record[:recordHeaderLen]
			} else {
				copy(additionalData, rr.seq[:])
				copy(additionalData[8:], record[:3])
				n := len(payload) - c.Overhead()
				additionalData[11] = byte(n >> 8)
				additionalData[12] = byte(n)
			}

			var err error
			plaintext, err = c.Open(payload[:0], nonce, payload, additionalData)
			if err != nil {
				return nil, 0, alertBadRecordMAC
			}
		case cbcMode:
			blockSize := c.BlockSize()
			minPayload := explicitNonceLen + roundUp(rr.mac.Size()+1, blockSize)
			if len(payload)%blockSize != 0 || len(payload) < minPayload {
				return nil, 0, alertBadRecordMAC
			}

			if explicitNonceLen > 0 {
				c.SetIV(payload[:explicitNonceLen])
				payload = payload[explicitNonceLen:]
			}
			c.CryptBlocks(payload, payload)

			// In a limited attempt to protect against CBC padding oracles like
			// Lucky13, the data past paddingLen (which is secret) is passed to
			// the MAC function as extra data, to be fed into the HMAC after
			// computing the digest. This makes the MAC roughly constant time as
			// long as the digest computation is constant time and does not
			// affect the subsequent write, modulo cache effects.
			paddingLen, paddingGood = extractPadding(payload)
		default:
			panic("unknown cipher type")
		}

		if rr.version == tls.VersionTLS13 {
			if typ != recordTypeApplicationData {
				return nil, 0, alertUnexpectedMessage
			}
			if len(plaintext) > maxPlaintext+1 {
				return nil, 0, alertRecordOverflow
			}
			// Remove padding and find the ContentType scanning from the end.
			for i := len(plaintext) - 1; i >= 0; i-- {
				if plaintext[i] != 0 {
					typ = recordType(plaintext[i])
					plaintext = plaintext[:i]
					break
				}
				if i == 0 {
					return nil, 0, alertUnexpectedMessage
				}
			}
		}
	} else {
		plaintext = payload
	}

	if rr.mac != nil {
		macSize := rr.mac.Size()
		if len(payload) < macSize {
			return nil, 0, alertBadRecordMAC
		}

		n := len(payload) - macSize - paddingLen
		n = subtle.ConstantTimeSelect(int(uint32(n)>>31), 0, n) // if n < 0 { n = 0 }
		record[3] = byte(n >> 8)
		record[4] = byte(n)
		remoteMAC := payload[n : n+macSize]
		localMAC := rr.mac.MAC(rr.seq[0:], record[:recordHeaderLen], payload[:n], payload[n+macSize:])

		// This is equivalent to checking the MACs and paddingGood
		// separately, but in constant-time to prevent distinguishing
		// padding failures from MAC failures. Depending on what value
		// of paddingLen was returned on bad padding, distinguishing
		// bad MAC from bad padding can lead to an attack.
		//
		// See also the logic at the end of extractPadding.
		macAndPaddingGood := subtle.ConstantTimeCompare(localMAC, remoteMAC) & int(paddingGood)
		if macAndPaddingGood != 1 {
			return nil, 0, alertBadRecordMAC
		}

		plaintext = payload[:n]
	}

	rr.incSeq()
	return plaintext, typ, nil
}

func (rr *rawReader) incSeq() {
	for i := 7; i >= 0; i-- {
		rr.seq[i]++
		if rr.seq[i] != 0 {
			return
		}
	}

	// Not allowed to let sequence number wrap.
	// Instead, must renegotiate before it does.
	// Not likely enough to bother.
	panic("TLS: sequence number wraparound")
}

func (rr *rawReader) explicitNonceLen() int {
	if rr.cipher == nil {
		return 0
	}

	switch c := rr.cipher.(type) {
	case cipher.Stream:
		return 0
	case aead:
		return c.explicitNonceLen()
	case cbcMode:
		// TLS 1.1 introduced a per-record explicit IV to fix the BEAST attack.
		if rr.version >= tls.VersionTLS11 {
			return c.BlockSize()
		}
		return 0
	default:
		panic("unknown cipher type")
	}
}

func (rr *rawReader) setTrafficSecret(suite *cipherSuiteTLS13, secret []byte) {
	rr.trafficSecret = secret
	key, iv := suite.trafficKey(secret)
	rr.cipher = suite.aead(key, iv)
	for i := range rr.seq {
		rr.seq[i] = 0
	}
}

func roundUp(a, b int) int {
	return a + (b-a%b)%b
}

func extractPadding(payload []byte) (toRemove int, good byte) {
	if len(payload) < 1 {
		return 0, 0
	}

	paddingLen := payload[len(payload)-1]
	t := uint(len(payload)-1) - uint(paddingLen)
	// if len(payload) >= (paddingLen - 1) then the MSB of t is zero
	good = byte(int32(^t) >> 31)

	// The maximum possible padding length plus the actual length field
	toCheck := 256
	// The length of the padded data is public, so we can use an if here
	if toCheck > len(payload) {
		toCheck = len(payload)
	}

	for i := 0; i < toCheck; i++ {
		t := uint(paddingLen) - uint(i)
		// if i <= paddingLen then the MSB of t is zero
		mask := byte(int32(^t) >> 31)
		b := payload[len(payload)-1-i]
		good &^= mask&paddingLen ^ mask&b
	}

	// We AND together the bits of good and replicate the result across
	// all the bits.
	good &= good << 4
	good &= good << 2
	good &= good << 1
	good = uint8(int8(good) >> 7)

	// Zero the padding length on error. This ensures any unchecked bytes
	// are included in the MAC. Otherwise, an attacker that could
	// distinguish MAC failures from padding failures could mount an attack
	// similar to POODLE in SSL 3.0: given a good ciphertext that uses a
	// full block's worth of padding, replace the final block with another
	// block. If the MAC check passed but the padding check failed, the
	// last byte of that block decrypted to the block size.
	//
	// See also macAndPaddingGood logic below.
	paddingLen &= good

	toRemove = int(paddingLen) + 1
	return
}
