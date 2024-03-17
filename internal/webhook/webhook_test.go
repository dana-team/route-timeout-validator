package webhook

import (
	"context"
	. "github.com/onsi/gomega"
	routev1 "github.com/openshift/api/route/v1"
	k8sadm "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/client-go/kubernetes/scheme"
	"os"
	ctrl "sigs.k8s.io/controller-runtime"
	testclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	"testing"
)

func TestRouteWebhook(t *testing.T) {
	webhookLog := ctrl.Log.WithName("webhook")
	tests := []struct {
		name         string
		timeoutValue string
		allowed      bool
		env          bool
		bypass       bool
	}{
		{name: "badSyntaxTimeoutRoute", timeoutValue: "1s1s", allowed: false, env: false},
		{name: "badSyntaxTimeoutRoute", timeoutValue: "s", allowed: false, env: false},
		{name: "badRangeTimeoutRange", timeoutValue: "1000s", allowed: false, env: false},
		{name: "goodTimeoutRoute", timeoutValue: "50s", allowed: true, env: false},
		{name: "goodEnvTimeoutRoute", timeoutValue: "440s", allowed: false, env: true},
		{name: "bypassTest", timeoutValue: "3000s", allowed: true, env: true, bypass: true},
	}

	bypassLabels := map[string]string{
		adminBypassTimeoutLabel: "true",
	}

	ns := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test1"}}
	client := testclient.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(&ns).Build()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			g := NewWithT(t)

			decoder := admission.NewDecoder(scheme.Scheme)
			rv := RouteValidator{Decoder: decoder, Log: webhookLog, Client: client}
			route := routev1.Route{}
			os.Setenv("secondsTimeout", "660")

			if tc.env {
				os.Setenv("secondsTimeout", "330")
			}

			if tc.bypass {
				ns.SetLabels(bypassLabels)
				_ = client.Update(ctx, &ns)
			}

			if tc.timeoutValue != "" {
				route = routev1.Route{
					ObjectMeta: metav1.ObjectMeta{
						Name:      tc.name,
						Namespace: "test1",
						Annotations: map[string]string{
							timeoutAnnotation: tc.timeoutValue,
						}},
				}
			}

			obj, err := json.Marshal(route)
			g.Expect(err).ShouldNot(HaveOccurred())
			req := admission.Request{AdmissionRequest: k8sadm.AdmissionRequest{
				Name:   tc.name,
				Kind:   metav1.GroupVersionKind{Kind: "Route", Group: "route.openshift.io", Version: "v1"},
				Object: runtime.RawExtension{Raw: obj},
			}}
			response := rv.Handle(ctx, req)
			g.Expect(response.Allowed).Should(Equal(tc.allowed))

		})
	}
}
