package goh4

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

//var supportedMethods = []string{"GET", "POST", "PUT"}

func hashSHA256(content []byte) string {
	h := sha256.New()
	h.Write(content)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func hmacSHA256(key []byte, content string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(content))
	return mac.Sum(nil)
}

func checksum(content string, request *http.Request) *http.Request {
	hash := hashSHA256([]byte(content))
	request.Header.Set("X-Tetration-Cksum", hash)

	return request
}

type H4 struct {
	Endpoint string
	Prefix   string
	Key      string
	Secret   string
	Verify   bool
}

func (h *H4) hash(request *http.Request) *http.Request {
	var buf bytes.Buffer
	buf.WriteString(request.Method)
	buf.WriteString("\n")
	buf.WriteString(request.URL.RequestURI())
	buf.WriteString("\n")
	buf.WriteString(request.Header.Get("X-Tetration-Cksum"))
	buf.WriteString("\n")
	buf.WriteString(request.Header.Get("Content-Type"))
	buf.WriteString("\n")
	buf.WriteString(request.Header.Get("Timestamp"))
	buf.WriteString("\n")

	hash := base64.StdEncoding.EncodeToString(hmacSHA256([]byte(h.Secret), buf.String()))
	request.Header.Set("Authorization", hash)

	return request
}

func (h *H4) url(path string) string {
	var buf bytes.Buffer
	buf.WriteString(h.Endpoint)
	buf.WriteString(h.Prefix)
	buf.WriteString(path)
	url := buf.String()

	return url
}

func (h *H4) sign(request *http.Request) *http.Request {

	request.Header.Set("User-Agent", "Cisco Tetration Go client")
	request.Header.Set("Timestamp", time.Now().UTC().Format("2006-01-02T15:04:05-0700"))
	request.Header.Set("Id", h.Key)

	return h.hash(request)
}

func (h *H4) Get(path string) []byte {
	var insecureVerify bool

	url := h.url(path)

	if h.Verify == false {
		insecureVerify = true
	} else {
		insecureVerify = false
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureVerify},
	}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal("NewRequest:", err)
	}
	h.sign(req)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Do:", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Readall:", err)
	}

	return body
}

func (h *H4) Post(path string, json string) []byte {
	var insecureVerify bool

	url := h.url(path)

	if h.Verify == false {
		insecureVerify = true
	} else {
		insecureVerify = false
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureVerify},
	}
	client := &http.Client{Transport: tr}
	reader := strings.NewReader(json)

	req, err := http.NewRequest("POST", url, reader)
	if err != nil {
		log.Fatal("NewRequest:", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Hash needs to be performed here, or the reader will mark it as closed
	// Can't read twice https://groups.google.com/forum/#!topic/golang-nuts/S6qQHDtoxgo
	checksum(json, req)

	h.sign(req)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Do:", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Readall:", err)
	}

	return body
}

func (h *H4) Put(path string, json string) []byte {
	var insecureVerify bool

	url := h.url(path)

	if h.Verify == false {
		insecureVerify = true
	} else {
		insecureVerify = false
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureVerify},
	}
	client := &http.Client{Transport: tr}
	reader := strings.NewReader(json)

	req, err := http.NewRequest("PUT", url, reader)
	if err != nil {
		log.Fatal("NewRequest:", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Hash needs to be performed here, or the reader will mark it as closed
	// Can't read twice https://groups.google.com/forum/#!topic/golang-nuts/S6qQHDtoxgo
	checksum(json, req)

	h.sign(req)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Do:", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Readall:", err)
	}

	return body
}

func (h *H4) Delete(path string, json string) []byte {
	var insecureVerify bool

	url := h.url(path)

	if h.Verify == false {
		insecureVerify = true
	} else {
		insecureVerify = false
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureVerify},
	}
	client := &http.Client{Transport: tr}
	reader := strings.NewReader(json)

	req, err := http.NewRequest("DELETE", url, reader)
	if err != nil {
		log.Fatal("NewRequest:", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Hash needs to be performed here, or the reader will mark it as closed
	// Can't read twice https://groups.google.com/forum/#!topic/golang-nuts/S6qQHDtoxgo
	// FIXME Not sure if this is needed for DELETE?
	checksum(json, req)

	h.sign(req)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Do:", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Readall:", err)
	}

	return body
}

func (h *H4) Upload(data []byte, add bool, ipVrfKey bool) []byte {

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	writer.SetBoundary("CiscoTetrationClient")
	if ipVrfKey {
		writer.WriteField("X-Tetration-Key", "[\"IP\", \"VRF\"]")
	} else {
		writer.WriteField("X-Tetration-Key", "[\"Hostname\"]")
	}
	if add {
		writer.WriteField("X-Tetration-Oper", "add")
	} else {
		writer.WriteField("X-Tetration-Oper", "delete")
	}

	part, err := writer.CreateFormFile("file", "filename")
	if err != nil {
		log.Fatal("Could not create multi-part form file header", err)
	}

	_, err = io.Copy(part, bytes.NewReader(data))
	if err != nil {
		log.Fatal("Could not copy data into multi-part form part", err)
	}

	writer.Close()

	insecureVerify := !h.Verify
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureVerify},
	}
	client := &http.Client{Transport: tr}

	url := h.url("/assets/cmdb/upload")
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		log.Fatal("NewRequest:", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	h.sign(req)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Do:", err)
	}
	defer resp.Body.Close()

	response_body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Readall:", err)
	}

	return response_body
}
