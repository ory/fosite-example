package authorizationserver

import (
	"github.com/ory/fosite"
	"log"
	"net/http"
)

func introspectionEndpoint(rw http.ResponseWriter, req *http.Request) {
	ctx := fosite.NewContext()
	mySessionData := newSession("")
	ir, err := oauth2.NewIntrospectionRequest(ctx, req, mySessionData)
	if err != nil {
		log.Printf("Error occurred in NewAuthorizeRequest: %s\nStack: \n%s", err, err.(stackTracer).StackTrace())
		oauth2.WriteIntrospectionError(rw, err)
		return
	}

	oauth2.WriteIntrospectionResponse(rw, ir)
}
