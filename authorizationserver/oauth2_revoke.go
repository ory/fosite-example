package authorizationserver

import (
	"net/http"

	"github.com/ory/fosite"
)

func revokeEndpoint(rw http.ResponseWriter, req *http.Request) {
	// This context will be passed to all methods.
	ctx := fosite.NewContext()

	// This will accept the token revocation request and validate various parameters.
	err := oauth2.NewRevocationRequest(ctx, req)

	// All done, send the response.
	oauth2.WriteRevocationResponse(rw, err)
}
