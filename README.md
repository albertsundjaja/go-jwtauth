# go-jwtauth
MIT License

A wrapper for authenticating [Julien Schmidt's router](https://github.com/julienschmidt/httprouter) with jwt

THIS IS A WORK IN PROGRESS

## Installation
`go get -u github.com/albertsundjaja/go-jwtauth`

## Docs
### How JWT Auth works

First, when user login with the correct username and password, we will issue a new cookie with JWT as its value. 
This JWT will contain claims of the user's identity (username, id, permissions, roles, privileges, etc). This claim will then be signed using server secret (this uses the package [jwt-go](https://github.com/dgrijalva/jwt-go)) so that any attempt to temper this claims will result in the token being invalid. Every time a user want to access a protected page, we will check this JWT for user's identity and permission WITHOUT having to query the DB each time since these identities are stored in the JWT.

### How to use
#### Initializing
```go
import jwtauth "github.com/albertsundjaja/go-jwtauth"

// first we declare a global variable that we can use accross our app
var myAuth jwtauth.JwtAuth

// initialize the required parameters
func init() {
  // ServerSecret is the string that will be used to sign our JWT, generating something random is recommended
	myAuth.ServerSecret = "abcdefg"
  // Whenever we have users with invalid JWT / no JWT set who access the protected page
  // we will redirect the user to this page
	myAuth.LoginRedirect = "/login"
  // This is the cookie key for storing the JWT
  // I prefer to change this to something unique that user don't expect what value it contains
  // because I'm just being paranoid ;)
	myAuth.CookieKey = "MyAuth"
}
```

#### Authenticating JWT (check if it has been tempered)
```go
// simply wrap the handler
router := httprouter.New()
router.GET("/protected", myAuth.ProtectPage(ProtectedPageHandler))
```

#### Setting cookie when user logged in
```go
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

  // we build the user claims 
	myClaims := map[string]interface{} {
		"Username":username,
		"Role":role,
		//add anything you want here, UserId, Role, Permission, etc
	}

  // create the JWT
	jwtToken, err := myAuth.CreateJwtToken(myClaims)
	if err != nil{
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	// set expiry to 7 days
	expiryCookie := time.Now().Add(7 * 24 * time.Hour)
	cookie := http.Cookie{Name:myAuth.CookieKey, Value:jwtToken, Expires: expiryCookie, HttpOnly:true}
  
  // set cookie to our writer
	http.SetCookie(w, &cookie)

	// redirect to index after logging in
	http.Redirect(w, req,"/", http.StatusSeeOther)
}
```

#### Using the claims in the JWT for authentication/permission
```go
func ProtectedPageHandler(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {

  // the wrapper ProtectPage, will add Context to the original request
  // this Context contains interface{} with key "Claims" 
  // Claims contains the user's claims which we set when the user logged in
	userClaims := req.Context().Value("Claims").(map[string]interface{})

	if userClaims["Role"] == "admin" {
		fmt.Fprint(w, "Hooray you can access this page")
	} else {
		fmt.Fprint(w, "You are not allowed to access this page")
	}

}
```
