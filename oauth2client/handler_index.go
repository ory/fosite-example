package oauth2client

import (
	"fmt"
	"net/http"

	goauth "golang.org/x/oauth2"
)

func HomeHandler(c goauth.Config) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			// The "/" pattern matches everything, so we need to check that
			// we're at the root here.
			return
		}

		// rotate PKCE secrets
		pkceCodeVerifier = generateCodeVerifier(64)
		pkceCodeChallenge = generateCodeChallenge(pkceCodeVerifier)

		rw.Write([]byte(fmt.Sprintf(`
		<p>You can obtain an access token using various methods</p>
		<ul>
			<li>
				<a href="%s">Authorize code grant (with OpenID Connect)</a>
			</li>
			<li>
				<a href="%s" onclick="setPKCE()">Authorize code grant (with OpenID Connect) with PKCE</a>
			</li>
			<li>
				<a href="%s">Implicit grant (with OpenID Connect)</a>
			</li>
			<li>
				Client credentials grant <a href="/client">using primary secret</a> or <a href="/client-new">using rotateted secret</a>
			</li>
			<li>
				<a href="/owner">Resource owner password credentials grant</a>
			</li>
			<li>
				<a href="%s">Refresh grant</a>. <small>You will first see the login screen which is required to obtain a valid refresh token.</small>
			</li>
			<li>
				<a href="%s">Make an invalid request</a>
			</li>
		</ul>

		<script type="text/javascript">
			function setPKCE() {
				// push in a cookie that the user-agent can check to see if last request was a PKCE request.
				document.cookie = '`+cookiePKCE+`=true';
			}
			
			(function(){
				// clear existing isPKCE cookie if returning to the home page.
				document.cookie = '`+cookiePKCE+`=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
			})();
		</script>`,
			c.AuthCodeURL("some-random-state-foobar")+"&nonce=some-random-nonce",
			c.AuthCodeURL("some-random-state-foobar")+"&nonce=some-random-nonce&code_challenge="+pkceCodeChallenge+"&code_challenge_method=S256",
			"http://localhost:3846/oauth2/auth?client_id=my-client&redirect_uri=http%3A%2F%2Flocalhost%3A3846%2Fcallback&response_type=token%20id_token&scope=fosite%20openid&state=some-random-state-foobar&nonce=some-random-nonce",
			c.AuthCodeURL("some-random-state-foobar")+"&nonce=some-random-nonce",
			"/oauth2/auth?client_id=my-client&scope=fosite&response_type=123&redirect_uri=http://localhost:3846/callback",
		)))
	}
}
