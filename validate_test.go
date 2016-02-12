package twilio_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jeremyschlatter/twilio-middleware"
)

func exampleRequest() *http.Request {
	r, _ := http.NewRequest("POST", "https://mycompany.com/myapp.php?foo=1&bar=2", strings.NewReader(url.Values{
		"Digits":  {"1234"},
		"To":      {"+18005551212"},
		"From":    {"+14158675309"},
		"Caller":  {"+14158675309"},
		"CallSid": {"CA1234567890ABCDE"},
	}.Encode()))
	r.Header.Set("X-Twilio-Signature", "RSOYDt4T1cUTdK1PDd93/VVr8B8=")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestIsValid(t *testing.T) {
	// Sanity check the example from https://www.twilio.com/docs/api/security
	if !twilio.IsValid([]byte("12345"), exampleRequest()) {
		t.Error("Twilio example request should validate, but it didn't")
	}

	// Should fail with a different key.
	if twilio.IsValid([]byte("55555"), exampleRequest()) {
		t.Error("Twilio example request should not validate with an incorrect key, but it did")
	}
}
