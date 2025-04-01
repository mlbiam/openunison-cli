package outokens

import (
	"encoding/json"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
)

// GenerateExecCredential takes an ID token as a string and returns a populated ExecCredential object.
func GenerateExecCredential(token string) (*v1beta1.ExecCredential, error) {
	expirationTimestamp := time.Now().Add(5 * time.Minute) // Adjust as needed

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

// MarshalExecCredential returns the JSON encoding of the ExecCredential.
func MarshalExecCredential(cred *v1beta1.ExecCredential) ([]byte, error) {
	return json.MarshalIndent(cred, "", "  ")
}
