package handsh

import (
	"crypto/tls"
	"fmt"
	"hash"
)

// TLSMsgParser https 数据的解析
type TLSMsgParser struct {
	ClientConfig *tls.Config
	// 保留client和server的hellomsg，这两个对拿到加密密钥至关重要
	clientHello     *clientHelloMsg
	serverHello     *serverHelloMsg
	transcript      hash.Hash
	selectedSuite   *cipherSuiteTLS13
	clientReader    *rawReader
	serverReader    *rawReader
	handshakeSecret []byte
	clientSecret    []byte
	serverSecret    []byte
	masterSecret    []byte
	trafficSecret   []byte
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
	if tlsMsg, ok := msg.(handshakeMessage); ok && pr.transcript != nil {
		pr.transcript.Write(tlsMsg.marshal())
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
		if pr.clientReader.version < tls.VersionTLS13 || pr.serverReader.version < tls.VersionTLS13 {
			break
		}
		pr.serverHello = tlsMsg
		if err := pr.establishHandKeyFirstTime(pr.clientHello, pr.serverHello); err != nil {
			logger.Err(err.Error())
			return
		}
		pr.clientReader.setTrafficSecret(pr.selectedSuite, pr.serverSecret)
		pr.serverReader.setTrafficSecret(pr.selectedSuite, pr.clientSecret)
	case *finishedMsg:
		if pr.clientReader.version < tls.VersionTLS13 || pr.serverReader.version < tls.VersionTLS13 {
			break
		}
		if isClient {
			// client read server finishedMsg 并且设置读取server数据的key
			suite := pr.selectedSuite
			pr.trafficSecret = suite.deriveSecret(pr.masterSecret,
				clientApplicationTrafficLabel, pr.transcript)
			serverSecret := suite.deriveSecret(pr.masterSecret,
				serverApplicationTrafficLabel, pr.transcript)
			pr.clientReader.setTrafficSecret(suite, serverSecret)
		} else {
			// server read client finishedMsg 设置server读取数据的key
			suite := pr.selectedSuite
			pr.serverReader.setTrafficSecret(suite, pr.trafficSecret)
		}
	}
}

// 因为获取密钥的过程需要使用clienthello和serverhello的摘要
// 故选择client读取到serverhello开始计算密钥
// 此逻辑参考tls握手客户端逻辑
// 第一次建立tls握手的key
func (pr *TLSMsgParser) establishHandKeyFirstTime(clientHello *clientHelloMsg, serverHello *serverHelloMsg) error {
	//
	suite := mutualCipherSuiteTLS13(clientHello.cipherSuites, serverHello.cipherSuite)
	pr.selectedSuite = suite
	// 计算clienthello和serverhello的摘要
	pr.transcript = suite.hash.New()
	pr.transcript.Write(clientHello.marshal())
	pr.transcript.Write(serverHello.marshal())
	curveID := curvePreferences(pr.ClientConfig)[0]
	if _, ok := curveForCurveID(curveID); curveID != tls.X25519 && !ok {
		return fmt.Errorf("tls: CurvePreferences includes unsupported curve")
	}
	params, err := generateECDHEParameters(crand(pr.ClientConfig), curveID)
	if err != nil {
		return err
	}
	sharedKey := params.SharedKey(serverHello.serverShare.data)
	if sharedKey == nil {
		return fmt.Errorf("tls: invalid server key share")
	}
	// debug handshake_client_tls13.go得到的结果
	earlySecret := suite.extract(nil, nil)
	handshakeSecret := suite.extract(sharedKey,
		suite.deriveSecret(earlySecret, "derived", nil))
	pr.handshakeSecret = handshakeSecret
	clientSecret := suite.deriveSecret(handshakeSecret,
		clientHandshakeTrafficLabel, pr.transcript)
	pr.clientSecret = clientSecret
	serverSecret := suite.deriveSecret(handshakeSecret,
		serverHandshakeTrafficLabel, pr.transcript)
	pr.serverSecret = serverSecret
	masterSecret := suite.extract(nil, suite.deriveSecret(handshakeSecret, "derived", nil))
	pr.masterSecret = masterSecret
	return nil
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
