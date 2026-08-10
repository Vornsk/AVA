// Package ca — 프로젝트 전용 CA 생성·로드 (cert-manager 씨앗, FR-2.9)
// - ca.crt / ca.key 가 없으면 새로 생성 (이 PC 전용, 공개 CA 아님)
// - goproxy 가 이 CA로 MITM 인증서를 발급하도록 연결
// - ca.key 는 민감정보 → 유출 금지 (실제 제품은 서버 암호화 보관)
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/elazarl/goproxy"
)

const (
	caCertFile = "ca.crt"
	caKeyFile  = "ca.key"
)

// Ensure: ca.crt/ca.key 준비(없으면 생성) 후 goproxy에 연결.
func Ensure() error {
	if !fileExists(caCertFile) || !fileExists(caKeyFile) {
		if err := generateCA(); err != nil {
			return fmt.Errorf("CA 생성 실패: %w", err)
		}
	}
	return loadCA()
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// 자체 서명 CA를 새로 만들어 ca.crt/ca.key 로 저장.
func generateCA() error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "proxy-poc PoC CA",
			Organization: []string{"proxy-poc"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	// ca.crt (공개 인증서)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(caCertFile, certPEM, 0644); err != nil {
		return err
	}

	// ca.key (개인키 — 민감)
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(caKeyFile, keyPEM, 0600); err != nil {
		return err
	}

	fmt.Printf("새 CA 생성됨: %s (지문 SHA-256: %s)\n", caCertFile, fingerprint(der))
	return nil
}

// ca.crt/ca.key 를 읽어 goproxy의 MITM CA로 설정.
func loadCA() error {
	certPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(caKeyFile)
	if err != nil {
		return err
	}

	caCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	if caCert.Leaf, err = x509.ParseCertificate(caCert.Certificate[0]); err != nil {
		return err
	}

	// goproxy가 이 CA로 대상별 인증서를 동적 발급하도록 전역 설정 교체
	goproxy.GoproxyCa = caCert
	tlsConfig := goproxy.TLSConfigFromCA(&caCert)
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsConfig}
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: tlsConfig}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: tlsConfig}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: tlsConfig}

	fmt.Printf("CA 로드됨: %s (지문 SHA-256: %s)\n", caCertFile, fingerprint(caCert.Certificate[0]))
	return nil
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	out := ""
	for i, b := range sum {
		if i > 0 {
			out += ":"
		}
		out += fmt.Sprintf("%02X", b)
	}
	return out
}
