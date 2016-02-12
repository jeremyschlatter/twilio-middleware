// Package twilio is a middleware library for TwiML apps.
//
// It makes it easy to authenticate that requests are coming from Twilio.
package twilio

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// IsValid validates that r is a genuine Twilio request rather than a spoofed
// request from a third party.
//
// Example usage:
//   func myTwiMLHandler(w http.ResponseWriter, r *http.Request) {
//	if !twilio.IsValid([]byte(myTwilioAuthToken), r) {
//		http.Error(w, "403 Forbidden", http.StatusForbidden)
//		return
//	}
//	...
//   }
//
// Reference: https://www.twilio.com/docs/api/security
func IsValid(twilioAuthToken []byte, r *http.Request) bool {

	// 1. Create a string that is your URL with the full query string.
	s := r.URL.String()

	if r.Method == "POST" {

		// 2. Sort the list of POST variables by the parameter name.
		r.ParseForm()
		vals := toURLValues(r.PostForm)
		sort.Sort(vals)

		// 3. Append each POST variable, name and value, to the string with no delimiters:
		concat := make([]string, len(vals))
		for i := range vals {
			concat[i] = vals[i][0] + vals[i][1]
		}
		s += strings.Join(concat, "")
	}

	// 4. Hash the resulting string using HMAC-SHA1, using your AuthToken as the key.
	hash := hmac.New(sha1.New, twilioAuthToken)
	hash.Write([]byte(s))
	computed := hash.Sum(nil)

	// 5. Now take the Base64 encoding of the hash value.
	// 6. Compare that to the hash Twilio sent in the X-Twilio-Signature HTTP header.
	//
	// We are going to slightly deviate from instructions here.
	// Twilio says to Base64 encode our hash and do a string compare to the HTTP header.
	// Instead, we'll Base64 _decode_ the header and do a constant-time byte comparison
	// of the MACs, to avoid timing attacks.

	received, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-Twilio-Signature"))

	return hmac.Equal(computed, received)
}

// Validate is a middleware function that validates that incoming requests
// are genuine Twilio requests rather than spoofed requests from a third party.
// If validation succeeds, protected will be called to handle the request.
//
// Optionally, you can pass a second handler that will be called if validation fails.
// This can be useful to test validation when you first turn it on, or to customize
// your failure response. If no second handler is passed, Validate will respond to
// invalid requests with 403 Forbidden.
//
// Example usage:
//   http.HandleFunc("/my-twiml-path", twilio.Validate(myAuthToken, myTwiMLHandler))
//
// Example usage with failure handler:
//   http.HandleFunc("/my-twiml-path", twilio.Validate(myAuthToken, myTwiMLHandler, func(w http.ResponseWriter, r *http.Request) {
//	log.Println("WARNING: Twilio Validation failed!")
//	// Proceeding anyway.
//	myTwiMLHandler(w, r)
//   })
//
// Reference: https://www.twilio.com/docs/api/security
func Validate(twilioAuthToken string, protected http.HandlerFunc, authFailed ...http.HandlerFunc) http.HandlerFunc {
	key := []byte(twilioAuthToken)
	var invalid http.HandlerFunc
	if authFailed == nil {
		invalid = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
		})
	} else {
		invalid = authFailed[0]
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if IsValid(key, r) {
			protected(w, r)
		} else {
			invalid(w, r)
		}
	}
}

type urlValues [][2]string

func toURLValues(v url.Values) urlValues {
	u := make(urlValues, 0, len(v))
	for name, vals := range v {
		val := ""
		if len(vals) > 0 {
			val = vals[0]
		}
		u = append(u, [2]string{name, val})
	}
	return u
}

func (u urlValues) Len() int           { return len(u) }
func (u urlValues) Swap(i, j int)      { u[i], u[j] = u[j], u[i] }
func (u urlValues) Less(i, j int) bool { return u[i][0] < u[j][0] }
