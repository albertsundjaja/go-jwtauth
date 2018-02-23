package go_jwtauth

import (
	"github.com/dgrijalva/jwt-go"
	"fmt"
)

// Accepts struct object to be used as claims
// Returns a JWT Token
func (j JwtAuth) CreateJwtToken(claims map[string]interface{}) (string, error) {

	jwtClaims := jwt.MapClaims{}
	jwtClaims = claims

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
	tokenString, err := token.SignedString([]byte(j.ServerSecret))

	if err != nil {
		return "", err
	}

	return tokenString, nil
}


func (j JwtAuth) ValidateJwtToken(jwtToken string) (map[string]interface{},error) {

	// Return a Token
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error){
		// Make sure token's signature wasn't changed
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return []byte(j.ServerSecret), nil
	})

	if err != nil {
		return nil,err
	}

	// get all claims value
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("Unable to parse claims")
	}

	return claims,nil

}


