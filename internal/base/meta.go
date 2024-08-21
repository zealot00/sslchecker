package base

const Version = "0.1.0"

type Result struct {
	Host         string            `json:"host"`
	Port         string            `json:"port"`
	Header       map[string]string `json:"header"`
	Cookie       map[string]string `json:"cookie"`
	CipherSuites map[uint16]string `json:"cipherSuites"`
}
