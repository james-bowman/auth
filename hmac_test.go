package auth

import (
	"testing"
	"net/http"
)

func TestGenerateDigest(t *testing.T) {
    message := ""
    expectedDigest := "1B2M2Y8AsgTpgAmY7PhCfg=="
    
    digest := generateDigest(message)

    if digest != expectedDigest {
    	t.Fail()
    }
}

func TestSign(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com", nil)
	// /api/v2/projects/[YOUR_PROJECT]/cards/[CARD_NUMBER].xml
	
	if err != nil {
		t.Error(err)
	}
	
	req.Header.Add(ContentTypeHeader, "application/xml")
	
	newReq, err := sign(*req, "jbowman", []byte("hsdofhw"))
	
	blankContentMD5 := req.Header.Get(ContentMD5Header)
	contentMD5 := newReq.Header.Get(ContentMD5Header)
	
	
	t.Logf("blankContentMD5: %s", blankContentMD5)
	t.Logf("contentMD5: %s", contentMD5)
	if len(blankContentMD5) > 0 || len(contentMD5) == 0 {
		t.Fail()
	}
}