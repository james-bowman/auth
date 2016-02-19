package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/md5"
	"encoding/base64"
	"io"
	"hash"
	"fmt"
	"net/http"
	"io/ioutil"
	"time"
)

const (
	ContentTypeHeader = "Content-Type"
	DateHeader = "Date"
	ContentMD5Header = "Content-MD5"
	AuthorizationHeader = "Authorization"
)

func applyHash(h hash.Hash, message string) string {
	io.WriteString(h, message)
	data := h.Sum(nil)
	str := base64.StdEncoding.EncodeToString(data)
	
	return str
}

func generateDigest(message string) (string) {
	msg := applyHash(md5.New(), message)
	return msg
}

func generateDigestForBody(body io.ReadCloser) (string, error) {
	var data []byte
	if body == nil {
		data = []byte("")
	} else {
		defer body.Close()
		var err error
		data, err = ioutil.ReadAll(body)
		if err != nil {
			return "", fmt.Errorf("Failed to read request body: %s", err.Error)
		}
	}
	contentMD5 := generateDigest(string(data))
	
	return contentMD5, nil
}

func generateHMAC(message string, key []byte) (string) {
	h := hmac.New(sha1.New, key)
	msg := applyHash(h, message)
	return msg
}

func Sign(request http.Request, id string, key []byte) (http.Request, error) {
	uri := request.URL.Path
	contentType, date := request.Header.Get(ContentTypeHeader), request.Header.Get(DateHeader)

	if date == "" {
		date = time.Now().Format(http.TimeFormat)
		request.Header.Add(DateHeader, date)
	}

	contentMD5 := request.Header.Get(ContentMD5Header)
	if contentMD5 == "" {
		contentMD5, err := generateDigestForBody(request.Body)
		if err != nil {
			return request, err
		}
		
		request.Header.Add(ContentMD5Header, contentMD5)
	}
	
	// 'content-type,content-MD5,request URI,timestamp'
	mac := contentType + "," + contentMD5 + "," + uri + "," + date
	
	hmac := generateHMAC(mac, key)
	request.Header.Add(AuthorizationHeader, "APIAuth " + id + ":" + hmac)
	
	return request, nil
}

func IsAuthentic(request http.Request, key []byte) (bool, error) {
	// if message is too old then fail
	requestDate := request.Header.Get(DateHeader)
	t, err := time.Parse(requestDate, http.TimeFormat)
	if err != nil {
		return false, err
	}
	
	// TODO: What if no date is included in the request?	
	age := time.Since(t)
	if age.Minutes() > 15 {
		return false, nil
	}

	// if message digest doesn't match then message is not authentic/tampered with
	contentMD5 := request.Header.Get(ContentMD5Header)
	if contentMD5 == "" {
		return false, nil
	}
	
	digest, err := generateDigestForBody(request.Body)
	if err != nil {
		return false, err
	}
	if digest != contentMD5 {
		return false, nil
	}
	
	// if signature doesn't match then message is not authentic
	

	return true, nil
}