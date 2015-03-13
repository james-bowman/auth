package auth

import (
	"testing"
	"net/http"
	"time"
	"bytes"
)

func TestGenerateDigest(t *testing.T) {
    message := ""
    // expected digest for empty string
    expectedDigest := "1B2M2Y8AsgTpgAmY7PhCfg=="
    
    digest := generateDigest(message)

    if digest != expectedDigest {
    	t.Fail()
    }
}

func TestSignAuthentic(t *testing.T) {
	key := []byte("hsdofhw")

	req, err := http.NewRequest("GET", "http://example.com", nil)
	// /api/v2/projects/[YOUR_PROJECT]/cards/[CARD_NUMBER].xml
	
	if err != nil {
		t.Error(err)
	}
	
	req.Header.Add(DateHeader, time.Now().Format(http.TimeFormat))
	req.Header.Add(ContentTypeHeader, "application/xml")
	
	newReq, err := sign(*req, "jbowman", key)
	
	if err != nil {
		t.Error(err)
	}
	
	if newReq.Header.Get(ContentMD5Header) != "1B2M2Y8AsgTpgAmY7PhCfg==" {
		t.Fail()
	}
	
	auth, err := authentic(newReq, key)
	
	if err != nil {
		t.Error(err)
	}
	
	if !auth {
		t.Fail()
	}
}

func TestSignChangedBody(t *testing.T) {
	key := []byte("hsdofhw")

	req, err := http.NewRequest("GET", "http://example.com", nil)
	// /api/v2/projects/[YOUR_PROJECT]/cards/[CARD_NUMBER].xml
	
	if err != nil {
		t.Error(err)
	}
	
	req.Header.Add(DateHeader, time.Now().Format(http.TimeFormat))
	req.Header.Add(ContentTypeHeader, "application/xml")
	
	newReq, err := sign(*req, "jbowman", key)
	
	if err != nil {
		t.Error(err)
	}
	
	req, err = http.NewRequest("GET", "http://example.com", bytes.NewBuffer([]byte("dummy request body")))
	req.Header.Add(ContentTypeHeader, newReq.Header.Get(ContentTypeHeader))
	req.Header.Add(DateHeader, newReq.Header.Get(DateHeader))
	req.Header.Add(ContentMD5Header, newReq.Header.Get(ContentMD5Header))
	req.Header.Add(AuthorizationHeader, newReq.Header.Get(AuthorizationHeader))
			
	auth, err := authentic(*req, key)
	
	if err != nil {
		t.Error(err)
	}
	
	if auth {
		t.Fail()
	}
}

func TestSignChangedSignature(t *testing.T) {

}