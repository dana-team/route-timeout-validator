package webhook

import (
	"context"
	"fmt"
	"github.com/go-logr/logr"
	routev1 "github.com/openshift/api/route/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"net/http"
	"os"
	"regexp"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	"strconv"
	"time"
)

// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch
// +kubebuilder:webhook:path=/validate-v1-route,mutating=false,failurePolicy=ignore,sideEffects=None,groups=route.openshift.io,resources=routes,verbs=create;update,versions=v1,name=routetimeout.dana.io,admissionReviewVersions=v1;v1beta1

type RouteValidator struct {
	Decoder *admission.Decoder
	Log     logr.Logger
	Client  client.Client
}

const (
	timeoutAnnotation        = "haproxy.router.openshift.io/timeout"
	adminBypassTimeoutLabel  = "haproxy.router.dana.io/bypass-timeout"
	MaxTimeoutSeconds        = "secondsTimeout"
	defaultMaxTimeoutSeconds = "600"
	bitSizeFloat             = 64
)

// Handle handles admission requests for routes.
func (r *RouteValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	log := r.Log.WithValues("webhook", "Route Webhook", "Name", req.Name)
	log.Info("webhook request received")

	route := routev1.Route{}
	if err := r.Decoder.Decode(req, &route); err != nil {
		log.Error(err, "failed to decode route object")
		return admission.Errored(http.StatusInternalServerError, err)
	}

	namespace := corev1.Namespace{}
	if err := r.Client.Get(ctx, types.NamespacedName{Name: route.Namespace}, &namespace); err != nil {
		log.Error(err, "failed to get namespace")
		return admission.Errored(http.StatusInternalServerError, err)
	}

	timeout, ok := route.Annotations[timeoutAnnotation]
	if !ok {
		return admission.Allowed("No timeout annotation is set on the route")
	}

	bypass := bypassExists(namespace)
	return r.handle(timeout, bypass)
}

// handle handles the timeout validation.
func (r *RouteValidator) handle(timeout string, bypass bool) admission.Response {
	if !validateTimeoutString(timeout) {
		return admission.Denied("The timeout annotation is invalid. Please use a valid format: <number><time unit> (e.g., '10s' for 10 seconds).")
	}

	maxTimeoutSeconds, err := r.getMaxTimeout()
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	overMax, err := isTimeoutOverMax(timeout, maxTimeoutSeconds)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	if !bypass && overMax {
		return admission.Denied(fmt.Sprintf("Timeout annotation value is invalid. The maximum seconds timeout is %v", maxTimeoutSeconds))
	}

	return admission.Allowed("Route is valid")
}

// bypassExists returns a bool indicating whether a timeout bypass label exists on the namespace.
func bypassExists(namespace corev1.Namespace) bool {
	value, ok := namespace.Labels[adminBypassTimeoutLabel]
	if ok && value == "true" {
		return true
	}

	return false
}

// validateTimeoutString checks if the given timeout string contains a valid time unit suffix.
// It iterates through a list of valid time units and checks if the timeout string matches any of them.
// If a match is found, it returns true; otherwise, it returns false.
func validateTimeoutString(timeout string) bool {
	timeUnits := []string{"s", "m", "us", "ms"}
	for _, unit := range timeUnits {
		regexCheck := `^\d+` + regexp.QuoteMeta(unit) + `$`
		if regexp.MustCompile(regexCheck).MatchString(timeout) {
			return true
		}
	}
	return false
}

// isTimeoutOverMax checks if the given timeout duration is over the specified maximum duration.
// It parses the timeout string into a time.Duration and compares it with the maximum duration in seconds.
func isTimeoutOverMax(timeout string, maxTimeoutSeconds float64) (bool, error) {
	duration, err := time.ParseDuration(timeout)
	if err != nil {
		return false, err
	}

	if duration.Seconds() > maxTimeoutSeconds {
		return true, nil
	}

	return false, nil
}

// getMaxTimeout retrieves the maximum timeout value from the environment variable MaxTimeoutSeconds.
// If the environment variable is not set, it falls back to a default value.
func (r *RouteValidator) getMaxTimeout() (float64, error) {
	maxSeconds := os.Getenv(MaxTimeoutSeconds)
	if maxSeconds == "" {
		maxSeconds = defaultMaxTimeoutSeconds
	}

	valueFloat, err := strconv.ParseFloat(maxSeconds, bitSizeFloat)
	if err != nil {
		return 0, err
	}
	return valueFloat, nil
}
