# sslchecker
When it is tormented by various compliance, it leaves a small tool for testing the TLS status of the corresponding address, the algorithm, the configuration of various header information, etc


# Usage 
go build main.go 
```
./main -h  
  -host string 
        host to connect to (default "127.0.0.1")  
  -outputpath string  
        if you chose json,you should set outputpath.default ./ (default "./")  
  -outputtype string  
        output type,you can use stdout or json,default stdout (default "stdout")  
  -port string  
        port to connect to (default "443")   
  -useragent string  
        user-agent  
```

# Options  
- host string
- port string
- outputpath string if you chose json, you should set outputpath.default ./
- outputtype striing output type,you can use stdout or json,default stdout. //TODO
- user-agent string ,default Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 ,you set user-agent for you need to specify 

# example
```
./main -host www.foobar.com -port 443
[+] TLS 1.2 is supported or enabled 
  Supported Cipher Suites:
    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

Testing specific cipher suites:
[+] Cipher Suite TLS_RSA_WITH_AES_256_GCM_SHA384 supported
[-] Cipher Suite TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA not supported
[-] Cipher Suite TLS_ECDHE_RSA_WITH_RC4_128_SHA not supported
[-] Cipher Suite TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 not supported
[+] Cipher Suite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 supported
[-] Cipher Suite TLS_RSA_WITH_RC4_128_SHA not supported
[-] Cipher Suite TLS_RSA_WITH_3DES_EDE_CBC_SHA not supported
[+] Cipher Suite TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 supported
[-] Cipher Suite TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 not supported
[-] Cipher Suite TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 not supported
[-] Cipher Suite TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA not supported
[-] Cipher Suite TLS_RSA_WITH_AES_256_CBC_SHA not supported
[-] Cipher Suite TLS_ECDHE_ECDSA_WITH_RC4_128_SHA not supported
[+] Cipher Suite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 supported
[-] Cipher Suite TLS_AES_128_GCM_SHA256 not supported
[-] Cipher Suite TLS_RSA_WITH_AES_128_CBC_SHA not supported
[-] Cipher Suite TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA not supported
[-] Cipher Suite TLS_ECDHE_RSA_WITH_3DES_EDCB_SHA not supported
[-] Cipher Suite TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA not supported
[-] Cipher Suite TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 not supported
[-] Cipher Suite TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 not supported
[+] Cipher Suite TLS_RSA_WITH_AES_128_CBC_SHA256 supported
[+] Cipher Suite TLS_RSA_WITH_AES_128_GCM_SHA256 supported
[+] Cookie: uc_session
    - Secure flag is set
    - HttpOnly flag is set
    - SameSite flag is LaxMode
[+] CSP is supported or enabled 
    - default-src 'self' 'unsafe-inline' 'unsafe-eval' blob: data: *.google.com *.ecs.yyy.com *.xxxx.com;frame-ancestors 'self'
[+] Content-Type is supported or enabled 
    - text/html; charset=UTF-8
[+] HSTS is supported or enabled 
    - max-age=63072000; includeSubdomains; preload
[+] XFO is supported or enabled 
    - SAMEORIGIN
