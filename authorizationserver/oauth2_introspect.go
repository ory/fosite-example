package authorizationserver

import (
	"log"
	"net/http"

	"github.com/ory/fosite"
)

func introspectionEndpoint(rw http.ResponseWriter, req *http.Request) {
	ctx := fosite.NewContext()
	mySessionData := newSession("")
	ir, err := oauth2.NewIntrospectionRequest(ctx, req, mySessionData)
	if err != nil {
		log.Printf("Error occurred in NewAuthorizeRequest: %+v", err)
		oauth2.WriteIntrospectionError(rw, err)
		return
	}

	oauth2.WriteIntrospectionResponse(rw, ir)
}
