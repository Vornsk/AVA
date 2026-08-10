// cert-manager 자동화 (FR-2.6 상태확인 · FR-2.7 자동설치 · FR-2.9 검증/정리).
// Windows 신뢰 저장소(현재 사용자 Root)를 certutil로 다룬다. (관리자 권한 불필요)
//
//	· 상태확인: 지문으로 이미 신뢰돼 있는지 (멱등)
//	· 설치: 미신뢰일 때만 addstore
//	· 정리: delstore
//	· 검증: 프록시 경유 HTTPS 요청으로 인터셉트+신뢰 확인, 실패 시 핀닝 가능성 표시
package ca

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

func caDER() ([]byte, error) {
	pemBytes, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%s PEM 파싱 실패", caCertFile)
	}
	return block.Bytes, nil
}

// Thumbprint — CA의 SHA-1 지문 (Windows 신뢰저장소 식별자).
func Thumbprint() (string, error) {
	der, err := caDER()
	if err != nil {
		return "", err
	}
	sum := sha1.Sum(der)
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}

// IsTrusted — CA가 현재 사용자 Root 저장소에 있는가 (FR-2.6).
func IsTrusted() (bool, error) {
	tp, err := Thumbprint()
	if err != nil {
		return false, err
	}
	// 있으면 exit 0, 없으면 non-zero
	if err := exec.Command("certutil", "-user", "-store", "Root", tp).Run(); err != nil {
		return false, nil
	}
	return true, nil
}

// Install — CA를 사용자 Root 저장소에 설치 (FR-2.7). 이미 있으면 건너뜀(멱등, FR-2.6).
func Install() error {
	trusted, err := IsTrusted()
	if err != nil {
		return err
	}
	if trusted {
		fmt.Println("CA 이미 신뢰됨 — 설치 건너뜀 (멱등)")
		return nil
	}
	out, err := exec.Command("certutil", "-addstore", "-user", "-f", "Root", caCertFile).CombinedOutput()
	if err != nil {
		return fmt.Errorf("설치 실패: %v: %s", err, out)
	}
	fmt.Println("CA 설치 완료 (사용자 Root 저장소)")
	return nil
}

// Uninstall — CA를 사용자 Root 저장소에서 제거 (FR-2.9 정리).
func Uninstall() error {
	tp, err := Thumbprint()
	if err != nil {
		return err
	}
	out, err := exec.Command("certutil", "-user", "-delstore", "Root", tp).CombinedOutput()
	if err != nil {
		return fmt.Errorf("제거 실패: %v: %s", err, out)
	}
	fmt.Println("CA 제거 완료")
	return nil
}

// Verify — 프록시 경유 HTTPS 요청으로 인터셉트+신뢰 검증 (FR-2.9). 프록시가 떠 있어야 함.
//
//	시스템 신뢰 저장소를 쓰는 클라이언트가 성공 = CA 신뢰됨 + 인터셉트 정상.
//	실패 = CA 미신뢰 또는 대상 인증서 핀닝 가능성.
func Verify(proxyAddr, testURL string) error {
	if !strings.HasPrefix(proxyAddr, "http") {
		host := proxyAddr
		if strings.HasPrefix(host, ":") {
			host = "127.0.0.1" + host
		}
		proxyAddr = "http://" + host
	}
	pu, err := url.Parse(proxyAddr)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, // 기본 = 시스템 신뢰 저장소
	}
	resp, err := client.Get(testURL)
	if err != nil {
		return fmt.Errorf("검증 실패 (CA 미신뢰 또는 핀닝 가능성): %w", err)
	}
	resp.Body.Close()
	fmt.Printf("검증 성공: %s (%d) — 인터셉트+CA 신뢰 정상\n", testURL, resp.StatusCode)
	return nil
}
