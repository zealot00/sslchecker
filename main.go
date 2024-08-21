package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sslchecker/internal/base"
	"sslchecker/lib"
	"time"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
)

func main() {
	//if len(os.Args) != 2 {
	//	fmt.Println("Usage: sslscan <hostname>")
	//	return
	//}
	args := base.InitFlags()
	output := lib.CommandLineOutput{}
	hostname := fmt.Sprintf("%s:%s", args.Host, args.Port)
	url := "https://" + hostname

	tlsVersions := map[uint16]string{
		tls.VersionSSL30: "SSL 3.0",
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
	}

	cipherSuites := map[uint16]string{
		lib.TLS_AES_128_GCM_SHA256:                        "TLS_AES_128_GCM_SHA256",
		lib.TLS_RSA_WITH_RC4_128_SHA:                      "TLS_RSA_WITH_RC4_128_SHA",
		lib.TLS_RSA_WITH_AES_128_CBC_SHA:                  "TLS_RSA_WITH_AES_128_CBC_SHA",
		lib.TLS_RSA_WITH_AES_256_CBC_SHA:                  "TLS_RSA_WITH_AES_256_CBC_SHA",
		lib.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		lib.TLS_RSA_WITH_3DES_EDE_CBC_SHA:                 "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		lib.TLS_RSA_WITH_AES_128_CBC_SHA256:               "TLS_RSA_WITH_AES_128_CBC_SHA256",
		lib.TLS_RSA_WITH_AES_128_GCM_SHA256:               "TLS_RSA_WITH_AES_128_GCM_SHA256",
		lib.TLS_RSA_WITH_AES_256_GCM_SHA384:               "TLS_RSA_WITH_AES_256_GCM_SHA384",
		lib.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:              "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		lib.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:          "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		lib.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:          "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		lib.TLS_ECDHE_RSA_WITH_RC4_128_SHA:                "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		lib.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:           "TLS_ECDHE_RSA_WITH_3DES_EDCB_SHA",
		lib.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		lib.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		lib.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:       "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		lib.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:         "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		lib.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:         "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		lib.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		lib.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:         "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		lib.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		lib.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	}

	headersToCheck := map[string]string{
		"Strict-Transport-Security":         "HSTS",
		"Content-Security-Policy":           "CSP",
		"X-Content-Type-Options":            "XCTO",
		"X-Frame-Options":                   "XFO",
		"Referrer-Policy":                   "Referrer Policy",
		"X-XSS-Protection":                  "X-XSS-Protection",
		"Permissions-Policy":                "Permissions Policy",
		"X-Download-Options":                "X-Download-Options",
		"Expect-CT":                         "Expect-CT",
		"X-Permitted-Cross-Domain-Policies": "X-Permitted-Cross-Domain-Policies",
		"Public-Key-Pins":                   "Public-Key-Pins (Deprecated)",
		"Feature-Policy":                    "Feature-Policy (Replaced by Permissions-Policy)",
		"X-UA-Compatible":                   "X-UA-Compatible",
		"Content-Type":                      "Content-Type",
		"Access-Control-Allow-Origin":       "CORS (Access-Control-Allow-Origin)",
		"Server":                            "Server",
		"X-Powered-By":                      "X-Powered-By",
		"X-Content-Duration":                "X-Content-Duration",
	}

	for version, versionName := range tlsVersions {
		conf := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         version,
			MaxVersion:         version,
		}

		conn, err := tls.DialWithDialer(&net.Dialer{
			Timeout: 5 * time.Second,
		}, "tcp", hostname, conf)

		if err != nil {
			output.IsDiskabledOrNotSupportStr(versionName)
			continue
		}

		output.IsEnabledOrSupportStr(versionName)
		fmt.Println("  Supported Cipher Suites:")

		//判断加密算法
		cipherstats := conn.ConnectionState()
		fmt.Printf("    - %s\n", tls.CipherSuiteName(cipherstats.CipherSuite))

		conn.Close()
	}

	fmt.Println("\nTesting specific cipher suites:")

	for suiteID, suiteName := range cipherSuites {
		conf := &tls.Config{
			InsecureSkipVerify: true,
			CipherSuites:       []uint16{suiteID},
		}

		conn, err := tls.DialWithDialer(&net.Dialer{
			Timeout: 5 * time.Second,
		}, "tcp", hostname, conf)

		if err != nil {
			fmt.Printf("[-] Cipher Suite %s not supported\n", suiteName)
		} else {
			fmt.Printf(Green+"[+]"+Reset+" Cipher Suite %s supported\n", suiteName)
			conn.Close()
		}
	}

	// 2. 检测 HSTS、CSP、XCTO、XFO 等安全头
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("Error fetching %s: %v\n", url, err)
		return
	}
	defer resp.Body.Close()

	// 检测响应头

	cookies := resp.Cookies()
	if len(cookies) > 0 {
		for _, cookie := range cookies {
			fmt.Printf("[+] Cookie: %s\n", cookie.Name)
			if cookie.Secure {
				fmt.Println("    - Secure flag is set")
			} else {
				fmt.Println("    - Secure flag is NOT set")
			}
			if cookie.HttpOnly {
				fmt.Println("    - HttpOnly flag is set")
			} else {
				fmt.Println("    - HttpOnly flag is NOT set")
			}
			if cookie.SameSite == http.SameSiteLaxMode {
				fmt.Println("    - SameSite flag is LaxMode")
			} else {
				fmt.Println("    - SameSite flag is NOT LaxMode")
			}
		}
	} else {
		//fmt.Println("[-] Cookies is not enabled")
		output.IsDiskabledOrNotSupportStr("Cookies")

	}

	for header, description := range headersToCheck {
		value := resp.Header.Get(header)
		if value != "" {
			output.IsEnabledOrSupportStr(description)
			//fmt.Printf("[+] %s is enabled:\n", description)
			fmt.Println("    -", value)
		} else {
			output.IsDiskabledOrNotSupportStr(description)
			//fmt.Printf("[-] %s is not enabled\n", description)

		}
	}
}
