package main

import (
	"fmt"
	"github.com/ory/fosite-example/authorizationserver"
	"github.com/ory/fosite-example/oauth2client"
	"github.com/ory/fosite-example/resourceserver"
	goauth "golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"log"
	"net/http"
	"os/exec"
)

// A valid oauth2 client (check the store) that additionally requests an OpenID Connect id token
var clientConf = goauth.Config{
	ClientID:     "my-client",
	ClientSecret: "foobar",
	RedirectURL:  "http://localhost:3846/callback",
	Scopes:       []string{"photos", "openid", "offline"},
	Endpoint: goauth.Endpoint{
		TokenURL: "http://localhost:3846/oauth2/token",
		AuthURL:  "http://localhost:3846/oauth2/auth",
	},
}

// The same thing (valid oauth2 client) but for using the cliend credentials grant
var appClientConf = clientcredentials.Config{
	ClientID:     "my-client",
	ClientSecret: "foobar",
	Scopes:       []string{"fosite"},
	TokenURL:     "http://localhost:3846/oauth2/token",
}

func main() {
	// navigation
	http.HandleFunc("/", HomeHandler(clientConf)) // show some links on the index

	// ### oauth2 server ###
	authorizationserver.RegisterHandlers() // the authorization server (fosite)

	// ### oauth2 client ###
	// the following handlers are oauth2 consumers
	http.HandleFunc("/client", oauth2client.ClientEndpoint(appClientConf)) // complete a client credentials flow
	http.HandleFunc("/owner", oauth2client.OwnerHandler(clientConf))       // complete a resource owner password credentials flow
	http.HandleFunc("/callback", oauth2client.CallbackHandler(clientConf)) // the oauth2 callback endpoint

	// ### protected resource ###
	http.HandleFunc("/protected", resourceserver.ProtectedEndpoint(appClientConf))

	fmt.Println("Please open your webbrowser at http://localhost:3846")
	_ = exec.Command("open", "http://localhost:3846").Run()
	log.Fatal(http.ListenAndServe(":3846", nil))
}

func HomeHandler(c goauth.Config) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte(fmt.Sprintf(`
		<p>You can obtain an access token using various methods</p>
		<ul>
			<li>
				<a href="%s">Authorize code grant (with OpenID Connect)</a>
			</li>
			<li>
				<a href="%s">Implicit grant (with OpenID Connect)</a>
			</li>
			<li>
				<a href="/client">Client credentials grant</a>
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
		</ul>`,
			c.AuthCodeURL("some-random-state-foobar")+"&nonce=some-random-nonce",
			"http://localhost:3846/oauth2/auth?client_id=my-client&redirect_uri=http%3A%2F%2Flocalhost%3A3846%2Fcallback&response_type=token%20id_token&scope=fosite%20openid&state=some-random-state-foobar&nonce=some-random-nonce",
			c.AuthCodeURL("some-random-state-foobar")+"&nonce=some-random-nonce",
			"/oauth2/auth?client_id=my-client&scope=fosite&response_type=123&redirect_uri=http://localhost:3846/callback",
		)))
	}
}
