package handsh

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
)

type processor interface {
	process(isClient bool, msg interface{}) error
}

// TLSMsgParser https 数据的解析
type TLSMsgParser struct {
	ClientConfig *tls.Config
	// 保留client和server的hellomsg，这两个对拿到加密密钥至关重要
	clientHello  *clientHelloMsg
	serverHello  *serverHelloMsg
	clientReader *rawReader
	serverReader *rawReader
	vers         uint16
	msgProcessor processor
}

// NewParser 。。
func NewParser(conf *tls.Config) *TLSMsgParser {
	pr := &TLSMsgParser{
		ClientConfig: conf,
		clientReader: &rawReader{
			isClient: true,
			logger:   client,
		},
		serverReader: &rawReader{
			logger: server,
		},
	}
	pr.clientReader.emit = pr.processMsg
	pr.serverReader.emit = pr.processMsg
	return pr
}

// Parse 交给指定reader读取数据
func (pr *TLSMsgParser) Parse(isClient bool, data []byte) {
	if isClient {
		pr.clientReader.parse(data)
	} else {
		pr.serverReader.parse(data)
	}
}

// LastCheck 检查数据是否解析完毕
func (pr *TLSMsgParser) LastCheck() error {
	// 防止数据有遗漏，再次check
	pr.clientReader.parse([]byte{})
	pr.serverReader.parse([]byte{})
	cn := pr.clientReader.rawData.Len()
	sn := pr.serverReader.rawData.Len()
	if cn > 0 || sn > 0 {
		// 仍然有数据打印错误
		return fmt.Errorf("client remain data: %d bytes, server remain data: %d bytes", cn, sn)
	}
	return nil
}

// 参考 handshake_client.go中的pickTLSVersion方法
func (pr *TLSMsgParser) pickTLSVersion(serverHello *serverHelloMsg) error {
	peerVer := serverHello.vers
	if serverHello.supportedVersion != 0 {
		peerVer = serverHello.supportedVersion
	}

	versions := make([]uint16, 0, 4)
	for _, v := range []uint16{
		tls.VersionTLS13,
		tls.VersionTLS12,
		tls.VersionTLS11,
		tls.VersionTLS10,
	} {
		c := pr.ClientConfig
		if c != nil && c.MinVersion != 0 && v < c.MinVersion {
			continue
		}
		if c != nil && c.MaxVersion != 0 && v > c.MaxVersion {
			continue
		}
		versions = append(versions, v)
	}

	for _, peerVersion := range []uint16{peerVer} {
		for _, v := range versions {
			if v == peerVersion {
				// 设置client和server的tlsversion
				pr.clientReader.version = v
				pr.serverReader.version = v
				pr.vers = v
				return nil
			}
		}
	}
	return fmt.Errorf("tls: server selected unsupported protocol version %x", peerVer)
}

func (pr *TLSMsgParser) processMsg(isClient bool, msg interface{}, err error) {
	logger := server
	if isClient {
		logger = client
	}
	if err != nil {
		logger.Err(err.Error())
		return
	}
	switch tlsMsg := msg.(type) {
	case *clientHelloMsg:
		pr.clientHello = tlsMsg
	case *serverHelloMsg:
		// client read server hello msg
		if err := pr.pickTLSVersion(tlsMsg); err != nil {
			logger.Err(err.Error())
			return
		}
		pr.serverHello = tlsMsg
		if pr.vers == tls.VersionTLS13 {
			pr.msgProcessor = &tls13Processor{
				tr: pr,
			}
		} else {
			pr.msgProcessor = &defalutProcessor{
				tr: pr,
			}
		}
	}
	// 读完serverhellomsg 之后tls版本才不为0
	if pr.vers == 0 {
		return
	}
	// 处理hellomsg 之外的信息解析解密信息
	pr.msgProcessor.process(isClient, msg)
}

type tls13Processor struct {
	tr              *TLSMsgParser
	transcript      hash.Hash
	selectedSuite   *cipherSuiteTLS13
	handshakeSecret []byte
	clientSecret    []byte
	serverSecret    []byte
	masterSecret    []byte
	trafficSecret   []byte
}

type defalutProcessor struct {
	tr               *TLSMsgParser
	selectedSuite    *cipherSuite
	peerCertificates []*x509.Certificate
	masterSecret     []byte
}

func (p *defalutProcessor) process(isClient bool, msg interface{}) error {
	tr := p.tr
	switch m := msg.(type) {
	case *serverHelloMsg:
		// 选择suite
		suite := mutualCipherSuite(tr.clientHello.cipherSuites, tr.serverHello.cipherSuite)
		if suite == nil {
			panic(errors.New("you have need to implements key exchange method"))
		}
		p.selectedSuite = suite
	case *certificateMsg:
		p.peerCertificates = make([]*x509.Certificate, len(m.certificates))
		for i, asn1Data := range m.certificates {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				return errors.New("tls: failed to parse certificate from server: " + err.Error())
			}
			p.peerCertificates[i] = cert
		}
	case *serverKeyExchangeMsg:
		keyAgreement := p.selectedSuite.ka(tr.vers)
		if err := keyAgreement.processServerKeyExchange(tr.ClientConfig, tr.clientHello, tr.serverHello, p.peerCertificates[0], m); err != nil {
			return err
		}
		preMasterSecret, _, err := keyAgreement.generateClientKeyExchange(tr.ClientConfig, tr.clientHello, p.peerCertificates[0])
		if err != nil {
			return err
		}
		p.masterSecret = masterFromPreMasterSecret(tr.vers, p.selectedSuite, preMasterSecret, tr.clientHello.random, tr.serverHello.random)
		suite := p.selectedSuite
		clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
			keysFromMasterSecret(tr.vers, suite, p.masterSecret, tr.clientHello.random, tr.serverHello.random, suite.macLen, suite.keyLen, suite.ivLen)
		var clientCipher, serverCipher interface{}
		var clientHash, serverHash macFunction
		if suite.cipher != nil {
			clientCipher = suite.cipher(clientKey, clientIV, true /* for reading */)
			clientHash = suite.mac(tr.vers, clientMAC)
			serverCipher = suite.cipher(serverKey, serverIV, true /* for reading */)
			serverHash = suite.mac(tr.vers, serverMAC)
		} else {
			clientCipher = suite.aead(clientKey, clientIV)
			serverCipher = suite.aead(serverKey, serverIV)
		}
		tr.clientReader.prepareCipherSpec(tr.vers, serverCipher, serverHash)
		tr.serverReader.prepareCipherSpec(tr.vers, clientCipher, clientHash)

	}
	return nil
}

func (p *tls13Processor) process(isClient bool, msg interface{}) error {
	if tlsMsg, ok := msg.(handshakeMessage); ok && p.transcript != nil {
		p.transcript.Write(tlsMsg.marshal())
	}
	tr := p.tr
	switch msg.(type) {
	case *serverHelloMsg:
		suite := mutualCipherSuiteTLS13(tr.clientHello.cipherSuites, tr.serverHello.cipherSuite)
		p.selectedSuite = suite
		// 计算clienthello和serverhello的摘要
		p.transcript = suite.hash.New()
		p.transcript.Write(tr.clientHello.marshal())
		p.transcript.Write(tr.serverHello.marshal())
		curveID := curvePreferences(tr.ClientConfig)[0]
		if _, ok := curveForCurveID(curveID); curveID != tls.X25519 && !ok {
			return fmt.Errorf("tls: CurvePreferences includes unsupported curve")
		}
		params, err := generateECDHEParameters(crand(tr.ClientConfig), curveID)
		if err != nil {
			return err
		}
		sharedKey := params.SharedKey(tr.serverHello.serverShare.data)
		if sharedKey == nil {
			return fmt.Errorf("tls: invalid server key share")
		}
		// debug handshake_client_tls13.go得到的结果
		earlySecret := suite.extract(nil, nil)
		p.handshakeSecret = suite.extract(sharedKey,
			suite.deriveSecret(earlySecret, "derived", nil))
		p.clientSecret = suite.deriveSecret(p.handshakeSecret,
			clientHandshakeTrafficLabel, p.transcript)
		p.serverSecret = suite.deriveSecret(p.handshakeSecret,
			serverHandshakeTrafficLabel, p.transcript)
		masterSecret := suite.extract(nil, suite.deriveSecret(p.handshakeSecret, "derived", nil))
		p.masterSecret = masterSecret

		tr.clientReader.setTrafficSecret(p.selectedSuite, p.serverSecret)
		tr.serverReader.setTrafficSecret(p.selectedSuite, p.clientSecret)
	case *finishedMsg:
		if isClient {
			// client read server finishedMsg 并且设置读取server数据的key
			suite := p.selectedSuite
			p.trafficSecret = suite.deriveSecret(p.masterSecret,
				clientApplicationTrafficLabel, p.transcript)
			serverSecret := suite.deriveSecret(p.masterSecret,
				serverApplicationTrafficLabel, p.transcript)
			tr.clientReader.setTrafficSecret(suite, serverSecret)
		} else {
			// server read client finishedMsg 设置server读取数据的key
			suite := p.selectedSuite
			tr.serverReader.setTrafficSecret(suite, p.trafficSecret)
		}
	}
	return nil
}
