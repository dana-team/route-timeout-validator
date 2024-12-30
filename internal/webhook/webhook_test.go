package webhook

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	routev1 "github.com/openshift/api/route/v1"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	testclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	certificatePlaceholder = "CERTIFICATE"
	organization           = "Company, INC."
	country                = "US"
	locality               = "San Francisco"
	privateKeyPlaceholder  = "RSA PRIVATE KEY"
)

// generateCertificate generates a self-signed certificate and returns its PEM-encoded certificate and private key.
func generateCertificateAndPrivateKey() (certPEM []byte, privateKey []byte, err error) {
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{organization},
			Country:      []string{country},
			Locality:     []string{locality},
		},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, err
	}

	certBuffer := new(bytes.Buffer)
	if err = pem.Encode(certBuffer, &pem.Block{
		Type:  certificatePlaceholder,
		Bytes: certBytes,
	}); err != nil {
		return nil, nil, err
	}
	privateKeyBuffer := new(bytes.Buffer)
	if err = pem.Encode(privateKeyBuffer, &pem.Block{
		Type:  privateKeyPlaceholder,
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}); err != nil {
		return nil, nil, err
	}

	return certBuffer.Bytes(), privateKeyBuffer.Bytes(), nil
}

func TestRouteWebhook(t *testing.T) {
	webhookLog := ctrl.Log.WithName("webhook")
	tests := []struct {
		name         string
		timeoutValue string
		allowed      bool
		bypass       bool
		tls          bool
		certificate  string
		privateKey   string
	}{
		{name: "badSyntaxTimeoutRoute", timeoutValue: "1s1s", allowed: false, bypass: false, tls: false, certificate: "", privateKey: ""},
		{name: "badSyntaxTimeoutRoute", timeoutValue: "s", allowed: false, bypass: false, tls: false, certificate: "", privateKey: ""},
		{name: "badRangeTimeoutRange", timeoutValue: "1000s", allowed: false, bypass: false, tls: false, certificate: "", privateKey: ""},
		{name: "goodTimeoutRoute", timeoutValue: "50s", allowed: true, bypass: false, tls: false, certificate: "", privateKey: ""},
		{name: "bypassTest", timeoutValue: "3000s", allowed: true, bypass: true, tls: false, certificate: "", privateKey: ""},
		{name: "goodTLS", timeoutValue: "50s", allowed: true, bypass: false, tls: true, certificate: "", privateKey: ""},
		{name: "badTLSCertificate", timeoutValue: "50s", allowed: false, bypass: false, tls: true, certificate: "BadCertificate", privateKey: ""},
		{name: "badTLSPrivateKey", timeoutValue: "50s", allowed: false, bypass: false, tls: true, certificate: "", privateKey: "BadPrivateKey"},
	}

	ns := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test1"}}
	client := testclient.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(&ns).Build()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			g.Expect(os.Setenv(MaxTimeoutSeconds, "660")).To(Succeed())
			decoder := admission.NewDecoder(scheme.Scheme)
			rv := RouteValidator{Decoder: decoder, Log: webhookLog, Client: client}
			config := &routev1.TLSConfig{}
			if tc.tls {
				certBytes, privateKeyBytes, err := generateCertificateAndPrivateKey()
				if err != nil {
					t.Errorf("Error generating certificate and private key: %v", err)
				}
				if tc.certificate == "" {
					config.Certificate = string(certBytes)
				} else {
					config.Certificate = tc.certificate
				}
				if tc.privateKey == "" {
					config.Key = string(privateKeyBytes)
				} else {
					config.Key = tc.privateKey
				}

			}
			response := rv.handle(tc.timeoutValue, tc.bypass, config)
			g.Expect(response.Allowed).Should(Equal(tc.allowed))
		})
	}
}
