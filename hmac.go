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


func generateHMAC(message string, key []byte) (string) {
	h := hmac.New(sha1.New, key)
	msg := applyHash(h, message)
	return msg
}

func sign(request http.Request, id string, key []byte) (http.Request, error) {
	uri := request.URL.Path
	contentType := request.Header.Get(ContentTypeHeader)
	date := request.Header.Get(DateHeader)

	contentMD5 := request.Header.Get(ContentMD5Header)
	if contentMD5 == "" {
		var body []byte
		if request.Body == nil {
			body = []byte("")
		} else {
			var err error
			body, err = ioutil.ReadAll(request.Body)
			if err != nil {
				return request, fmt.Errorf("Failed to read request body: %s", err.Error)
			}
		}
		contentMD5 = generateDigest(string(body))
	}
	request.Header.Add(ContentMD5Header, contentMD5)
	
	// 'content-type,content-MD5,request URI,timestamp'
	mac := contentType + "," + contentMD5 + "," + uri + "," + date
	
	hmac := generateHMAC(mac, key)
	request.Header.Add(AuthorizationHeader, "APIAuth " + id + ":" + hmac)
	
	return request, nil
}