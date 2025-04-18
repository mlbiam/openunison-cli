package outokens

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

// GenerateExecCredential takes an ID token as a string and returns a populated ExecCredential object.
func GenerateExecCredential(token string, forceBeta bool) (*v1beta1.ExecCredential, error) {
	expirationTimestamp, err := getExpirationTimestamp(token)

	if err != nil {
		return nil, fmt.Errorf("failed to get expiration timestamp: %w", err)
	}
	// If the token is expired, return an error

	if forceBeta {
		return &v1beta1.ExecCredential{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "client.authentication.k8s.io/v1beta1",
				Kind:       "ExecCredential",
			},
			Status: &v1beta1.ExecCredentialStatus{
				ExpirationTimestamp: &metav1.Time{Time: expirationTimestamp},
				Token:               token,
			},
		}, nil
	} else {

		return &v1beta1.ExecCredential{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "client.authentication.k8s.io/v1",
				Kind:       "ExecCredential",
			},
			Status: &v1beta1.ExecCredentialStatus{
				ExpirationTimestamp: &metav1.Time{Time: expirationTimestamp},
				Token:               token,
			},
		}, nil
	}
}

// MarshalExecCredential returns the JSON encoding of the ExecCredential.
func MarshalExecCredential(cred *v1beta1.ExecCredential) ([]byte, error) {
	return json.MarshalIndent(cred, "", "  ")
}

// Gets the expiration timestamp from the token string.
func getExpirationTimestamp(tokenString string) (time.Time, error) {
	// We don't need to validate the token for this use case, just parse the claims
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return time.Time{}, fmt.Errorf("invalid claims")
	}

	expRaw, ok := claims["exp"]
	if !ok {
		return time.Time{}, fmt.Errorf("no exp claim in token")
	}

	// exp can be float64 or json.Number
	var expUnix int64
	switch v := expRaw.(type) {
	case float64:
		expUnix = int64(v)
	case json.Number:
		var err error
		expUnix, err = v.Int64()
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid exp format: %w", err)
		}
	default:
		return time.Time{}, fmt.Errorf("unsupported exp type: %T", expRaw)
	}

	expTime := time.Unix(expUnix, 0).UTC()
	return expTime, nil
}
