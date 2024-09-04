package scanner

import (
	"fmt"
	"net/http"
	"time"

	"sslchecker/lib"
)

type HeaderChecker struct {
	HttpClient     *http.Client
	HeadersToCheck map[string]string
	UserAgent      string
	Url            string
	Output         lib.CommandLineOutput
}

func (h *HeaderChecker) GoToCheckHeader() {
	req, err := http.NewRequest("GET", h.Url, nil)
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return
	}
	req.Header.Add("User-Agent", h.UserAgent)
	resp, err := h.HttpClient.Do(req)
	if err != nil {
		fmt.Printf("Error fetching %s: %v\n", h.Url, err)
		return
	}

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
		h.Output.IsDiskabledOrNotSupportStr("Cookies")

	}

	for header, description := range h.HeadersToCheck {
		value := resp.Header.Get(header)
		if value != "" {
			h.Output.IsEnabledOrSupportStr(description)
			//fmt.Printf("[+] %s is enabled:\n", description)
			fmt.Println("    -", value)
		} else {
			h.Output.IsDiskabledOrNotSupportStr(description)
			//fmt.Printf("[-] %s is not enabled\n", description)

		}
	}

	defer resp.Body.Close()
}

func NewHeaderChecker(ua, url string) HeaderChecker {
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
	return HeaderChecker{
		HttpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		HeadersToCheck: headersToCheck,
		UserAgent:      ua,
		Url:            url,
		Output:         lib.CommandLineOutput{},
	}
}
