package oauth2client

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"net/http"
	"time"
)

// The following provides the setup required for the client to perform the "Authorization Code" flow with PKCE in order
// to obtain an access token for public/untrusted clients.

const cookiePKCE = "isPKCE"

var (
	// pkceCodeVerifier stores the generated random value which the client will on-send to the auth server with the received
	// authorization code. This way the oauth server can verify that the base64URLEncoded(sha265(codeVerifier)) matches
	// the stored code challenge, which was initially sent through with the code+PKCE authorization request to ensure
	// that this is the original user-agent who requested the access token.
	pkceCodeVerifier string

	// pkceCodeChallenge stores the base64(sha256(codeVerifier)) which is sent from the
	// client to the auth server as required for PKCE.
	pkceCodeChallenge string
)

// The following sets up the requirements for generating a standards compliant PKCE code verifier.
const codeVerifierLenMin = 43
const codeVerifierLenMax = 128
const codeVerifierAllowedLetters = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ._~"

// generateCodeVerifier provides an easy way to generate an n-length randomised
// code verifier.
func generateCodeVerifier(n int) string {
	// Enforce standards compliance...
	if n < codeVerifierLenMin {
		n = codeVerifierLenMin
	}
	if n > codeVerifierLenMax {
		n = codeVerifierLenMax
	}

	// Randomly choose some allowed characters...
	b := make([]byte, n)
	for i := range b {
		// ensure we use non-deterministic random ints.
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(len(codeVerifierAllowedLetters))))
		b[i] = codeVerifierAllowedLetters[j.Int64()]
	}

	return string(b)
}

// generateCodeChallenge returns a standards compliant PKCE S(HA)256 code
// challenge.
func generateCodeChallenge(codeVerifier string) string {
	// Create a sha-265 hash from the code verifier...
	s256 := sha256.New()
	s256.Write([]byte(codeVerifier))

	// Then base64 encode the hash sum to create a code challenge...
	return base64.RawURLEncoding.EncodeToString(s256.Sum(nil))
}

// isPKCE detects whether a PKCE auth request was made.
func isPKCE(r *http.Request) bool {
	cookie, err := r.Cookie(cookiePKCE)
	if err != nil {
		return false
	}

	return cookie.Value == "true"
}

// resetPKCE cleans up PKCE details and returns the code verifier.
func resetPKCE(w http.ResponseWriter) (codeVerifier string) {
	// remove cookie that informs the client the callback request was a PKCE
	// request.
	http.SetCookie(w, &http.Cookie{
		Name:    cookiePKCE,
		Path:    "/",
		Expires: time.Unix(0, 0),
	})

	codeVerifier = pkceCodeVerifier
	pkceCodeVerifier = ""

	return codeVerifier
}
