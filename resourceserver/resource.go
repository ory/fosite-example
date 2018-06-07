package resourceserver

import (
	"fmt"
	"net/http"

	"encoding/json"
	"io/ioutil"
	"net/url"
	"strings"

	"golang.org/x/net/context"
	"golang.org/x/oauth2/clientcredentials"
)

type session struct {
	User string
}

func ProtectedEndpoint(c clientcredentials.Config) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		resp, err := c.Client(context.Background()).PostForm(strings.Replace(c.TokenURL, "token", "introspect", -1), url.Values{"token": []string{req.URL.Query().Get("token")}, "scope": []string{req.URL.Query().Get("scope")}})
		if err != nil {
			fmt.Fprintf(rw, "<h1>An error occurred!</h1><p>Could not perform introspection request: %v</p>", err)
			return
		}
		defer resp.Body.Close()

		var introspection = struct {
			Active bool `json:"active"`
		}{}
		out, _ := ioutil.ReadAll(resp.Body)
		if err := json.Unmarshal(out, &introspection); err != nil {
			fmt.Fprintf(rw, "<h1>An error occurred!</h1>%s\n%s", err.Error(), out)
			return
		}

		if !introspection.Active {
			fmt.Fprint(rw, `<h1>Request could not be authorized.</h1>
<a href="/">return</a>`)
			return
		}

		fmt.Fprintf(rw, `<h1>Request authorized!</h1>
<code>%s</code><br>
<hr>
<a href="/">return</a>
`,
			out,
		)
	}
}
