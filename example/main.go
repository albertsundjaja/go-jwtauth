package main

import (
	jwtauth "github.com/albertsundjaja/go-jwtauth"
	"net/http"
	"github.com/julienschmidt/httprouter"
	"html/template"
	"fmt"
	"time"
	"log"

)

var myAuth jwtauth.JwtAuth
var TPL *template.Template

func init() {
	myAuth.ServerSecret = "abcdefg"
	myAuth.LoginRedirect = "/login"
	myAuth.CookieKey = "MyAuth"

	TPL = template.Must(template.ParseGlob("template/*.gohtml"))
}

func main() {
	router := httprouter.New()
	router.GET("/", Main_GET)
	router.GET("/login", Login_GET)
	router.POST("/login", Login_POST)
	router.GET("/protected", myAuth.ProtectPage(Protected_GET))
	log.Fatal(http.ListenAndServe(":8080", router))
}

func Main_GET(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	TPL.ExecuteTemplate(w, "main.gohtml", nil)
}

func Login_GET(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	TPL.ExecuteTemplate(w, "login.gohtml", nil)
}

func Login_POST(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {

	username := req.FormValue("username")
	password := req.FormValue("password")

	// this is where we query our DB to check username and password matches
	// and get user data to be used in claims
	validated, role := ValidateUserPass(username, password)

	if !validated {
		fmt.Fprint(w, "Username / password is wrong")
		return
	}

	myClaims := map[string]interface{} {
		"Username":username,
		"Role":role,
		//add anything you want here, UserId, Role, Permission, etc
	}

	jwtToken, err := myAuth.CreateJwtToken(myClaims)
	// jwttoken creation fails
	if err != nil{
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	// set expiry to 7 days
	expiryCookie := time.Now().Add(7 * 24 * time.Hour)
	cookie := http.Cookie{Name:myAuth.CookieKey, Value:jwtToken, Expires: expiryCookie, HttpOnly:true}
	http.SetCookie(w, &cookie)

	// redirect to root /
	http.Redirect(w, req,"/", http.StatusSeeOther)
}

func Protected_GET(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {

	// if role claims is 1, then this user is allowed to access this page
	userClaims := req.Context().Value("Claims").(map[string]interface{})

	if userClaims["Role"] == "admin" {
		fmt.Fprint(w, "Hooray you can access this page")
	} else {
		fmt.Fprint(w, "You are not allowed to access this page")
	}

}

// this is an example function to query the DB
// query the DB for this user info
// validate if username and password matches, get user's role etc
func ValidateUserPass(username string, password string) (bool, string) {
	// do validation of username and password

	// this is to demonstrate that if role != 1, user cant access the protected page
	// try login with username john77
	if (username == "john77") {
		return true, "admin"
	}

	return true, "unknown"
}
