package webhook

import (
	"os"
	"testing"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	testclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestRouteWebhook(t *testing.T) {
	webhookLog := ctrl.Log.WithName("webhook")
	tests := []struct {
		name         string
		timeoutValue string
		allowed      bool
		bypass       bool
	}{
		{name: "badSyntaxTimeoutRoute", timeoutValue: "1s1s", allowed: false, bypass: false},
		{name: "badSyntaxTimeoutRoute", timeoutValue: "s", allowed: false, bypass: false},
		{name: "badRangeTimeoutRange", timeoutValue: "1000s", allowed: false, bypass: false},
		{name: "goodTimeoutRoute", timeoutValue: "50s", allowed: true, bypass: false},
		{name: "bypassTest", timeoutValue: "3000s", allowed: true, bypass: true},
	}

	ns := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test1"}}
	client := testclient.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(&ns).Build()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			g.Expect(os.Setenv(MaxTimeoutSeconds, "660")).To(Succeed())
			decoder := admission.NewDecoder(scheme.Scheme)
			rv := RouteValidator{Decoder: decoder, Log: webhookLog, Client: client}

			response := rv.handle(tc.timeoutValue, tc.bypass)
			g.Expect(response.Allowed).Should(Equal(tc.allowed))

		})
	}
}
