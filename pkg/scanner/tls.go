package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"sslchecker/lib"
	"sslchecker/pkg/cli"
	"time"
)

const (
	// TLS 1.0 - 1.2 cipher suites.
	TLS_RSA_WITH_RC4_128_SHA                      uint16 = 0x0005
	TLS_RSA_WITH_3DES_EDE_CBC_SHA                 uint16 = 0x000a
	TLS_RSA_WITH_AES_128_CBC_SHA                  uint16 = 0x002f
	TLS_RSA_WITH_AES_256_CBC_SHA                  uint16 = 0x0035
	TLS_RSA_WITH_AES_128_CBC_SHA256               uint16 = 0x003c
	TLS_RSA_WITH_AES_128_GCM_SHA256               uint16 = 0x009c
	TLS_RSA_WITH_AES_256_GCM_SHA384               uint16 = 0x009d
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA              uint16 = 0xc007
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA          uint16 = 0xc009
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          uint16 = 0xc00a
	TLS_ECDHE_RSA_WITH_RC4_128_SHA                uint16 = 0xc011
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA           uint16 = 0xc012
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            uint16 = 0xc013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            uint16 = 0xc014
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256       uint16 = 0xc023
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256         uint16 = 0xc027
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         uint16 = 0xc02f
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       uint16 = 0xc02b
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         uint16 = 0xc030
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       uint16 = 0xc02c
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   uint16 = 0xcca8
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 uint16 = 0xcca9

	// TLS 1.3 cipher suites.
	TLS_AES_128_GCM_SHA256       uint16 = 0x1301
	TLS_AES_256_GCM_SHA384       uint16 = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 uint16 = 0x1303

	// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
	// that the client is doing version fallback. See RFC 7507.
	TLS_FALLBACK_SCSV uint16 = 0x5600

	// Legacy names for the corresponding cipher suites with the correct _SHA256
	// suffix, retained for backward compatibility.
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305   = TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 = TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
)

type SslChecker struct {
	Hostname    string
	TLSVersion  map[uint16]string
	CipherSuite map[uint16]string
	Output      *lib.CommandLineOutput
}

func (s *SslChecker) GoToCheckVersion() {
	for version, versionName := range s.TLSVersion {
		conf := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         version,
			MaxVersion:         version,
		}
		conn, err := tls.DialWithDialer(&net.Dialer{
			Timeout: 5 * time.Second,
		}, "tcp", s.Hostname, conf)

		if err != nil {
			s.Output.IsDiskabledOrNotSupportStr(versionName)
			continue
		}

		s.Output.IsEnabledOrSupportStr(versionName)
		fmt.Println("  Supported Cipher Suites:")

		//测试当前加密协议
		cipherStatus := conn.ConnectionState()
		fmt.Printf("    - %s\n", tls.CipherSuiteName(cipherStatus.CipherSuite))

		conn.Close()
	}
}

func (s *SslChecker) GoToCheckCipherSuite() {
	fmt.Println("\nTesting specific cipher suites:")
	for suiteID, suiteName := range s.CipherSuite {
		conf := &tls.Config{
			InsecureSkipVerify: true,
			CipherSuites:       []uint16{suiteID},
		}
		conn, err := tls.DialWithDialer(&net.Dialer{
			Timeout: 5 * time.Second,
		}, "tcp", s.Hostname, conf)
		if err != nil {
			fmt.Printf("[-] Cipher Suite %s not supported\n", suiteName)
		} else {
			fmt.Printf(cli.Green+"[+]"+cli.Reset+" Cipher Suite %s supported\n", suiteName)
			conn.Close()
		}
	}
}
func NewSslChecker(hostname string) SslChecker {
	tlsVersions := map[uint16]string{
		tls.VersionSSL30: "SSL 3.0",
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
	}
	cipherSuites := map[uint16]string{
		TLS_AES_128_GCM_SHA256:                        "TLS_AES_128_GCM_SHA256",
		TLS_RSA_WITH_RC4_128_SHA:                      "TLS_RSA_WITH_RC4_128_SHA",
		TLS_RSA_WITH_AES_128_CBC_SHA:                  "TLS_RSA_WITH_AES_128_CBC_SHA",
		TLS_RSA_WITH_AES_256_CBC_SHA:                  "TLS_RSA_WITH_AES_256_CBC_SHA",
		TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		TLS_RSA_WITH_3DES_EDE_CBC_SHA:                 "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		TLS_RSA_WITH_AES_128_CBC_SHA256:               "TLS_RSA_WITH_AES_128_CBC_SHA256",
		TLS_RSA_WITH_AES_128_GCM_SHA256:               "TLS_RSA_WITH_AES_128_GCM_SHA256",
		TLS_RSA_WITH_AES_256_GCM_SHA384:               "TLS_RSA_WITH_AES_256_GCM_SHA384",
		TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:              "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:          "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:          "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		TLS_ECDHE_RSA_WITH_RC4_128_SHA:                "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:           "TLS_ECDHE_RSA_WITH_3DES_EDCB_SHA",
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:       "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:         "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:         "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:         "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	}

	return SslChecker{
		Hostname:    hostname,
		TLSVersion:  tlsVersions,
		CipherSuite: cipherSuites,
		Output:      &lib.CommandLineOutput{},
	}

}
