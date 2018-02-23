package go_jwtauth

import (
	"net/http"
	"context"
	"github.com/julienschmidt/httprouter"
)

func (j JwtAuth) ProtectPage(protectedPage httprouter.Handle) httprouter.Handle {

	return httprouter.Handle(func(w http.ResponseWriter, req *http.Request, ps httprouter.Params){

		// If no Auth cookie is set then redirect to login page
		jwtCookie, err := req.Cookie(j.CookieKey)
		if err != nil {
			http.Redirect(w, req, j.LoginRedirect, http.StatusSeeOther)
			return
		}

		claims, err := j.ValidateJwtToken(jwtCookie.Value)
		if err != nil {
			http.Redirect(w, req, j.LoginRedirect, http.StatusSeeOther)
			return
		}

		//create a context containing the claims, with key Claims
		ctx := context.WithValue(req.Context(), "Claims", claims)

		//open the protected page and give the context containing the claim
		protectedPage(w, req.WithContext(ctx), ps)
	})
}
