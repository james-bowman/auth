package auth

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"time"
)

const (
	ContentTypeHeader   = "Content-Type"
	DateHeader          = "Date"
	ContentMD5Header    = "Content-MD5"
	AuthorizationHeader = "Authorization"
)

func applyHash(h hash.Hash, message string) string {
	io.WriteString(h, message)
	data := h.Sum(nil)
	str := base64.StdEncoding.EncodeToString(data)

	return str
}

func generateDigest(message string) string {
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

func generateHMAC(contentType string, contentMD5 string, uri string, date string, key []byte) string {
	// 'content-type,content-MD5,request URI,timestamp'
	message := contentType + "," + contentMD5 + "," + uri + "," + date

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
		var err error
		contentMD5, err = generateDigestForBody(request.Body)
		if err != nil {
			return request, err
		}
		request.Header.Add(ContentMD5Header, contentMD5)
	}

	hmac := generateHMAC(contentType, contentMD5, uri, date, key)
	request.Header.Add(AuthorizationHeader, "APIAuth "+id+":"+hmac)

	return request, nil
}

func IsAuthentic(request http.Request, key []byte) (bool, error) {
	// if message is too old then fail
	requestDate := request.Header.Get(DateHeader)

	if requestDate == "" {
		return false, nil
	}

	t, err := time.Parse(http.TimeFormat, requestDate)
	if err != nil {
		return false, err
	}

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

	authRE := regexp.MustCompile("APIAuth ([^:]+):(.+)$")
	authString := request.Header.Get(AuthorizationHeader)

	if authString == "" || !authRE.MatchString(authString) {
		return false, err
	}

	// if signature doesn't match then message is not authentic
	requestHMAC := authRE.FindStringSubmatch(authString)[2]
	hmac := generateHMAC(request.Header.Get(ContentTypeHeader), contentMD5, request.URL.Path, requestDate, key)
	if hmac != requestHMAC {
		return false, nil
	}

	return true, nil
}
