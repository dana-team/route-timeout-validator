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
)

// +kubebuilder:rbac:groups="",resources=secrets;namespaces,verbs=get;list;watch
// +kubebuilder:webhook:path=/validate-v1-route,mutating=false,failurePolicy=ignore,sideEffects=None,groups=route.openshift.io,resources=routes,verbs=create;update,versions=v1,name=routetimeout.dana.io,admissionReviewVersions=v1;v1beta1

type RouteValidator struct {
	Decoder *admission.Decoder
	Log     logr.Logger
	Client  client.Client
}

const (
	timeoutAnnotation       = "haproxy.router.openshift.io/timeout"
	adminBypassTimeoutLabel = "haproxy.router.dana.io/bypass-timeout"
)

// validateTimeoutString returns a bool indicating whether the timeout value
// suits the limit, in accordance with the env variables
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

func validateTimeoutRange(timeout string) (bool, error) {
	re := regexp.MustCompile(`^(\d+)([a-zA-Z]+)`)
	match := re.FindStringSubmatch(timeout)

	if len(match) > 2 {
		number := match[1]
		num, err := strconv.Atoi(number)
		if err != nil {
			return false, err
		}

		unit := match[2]
		seconds, err := strconv.Atoi(os.Getenv("secondsTimeout"))
		if err != nil {
			return false, err
		}

		minutes := seconds / 60
		ms := seconds * 1000
		us := ms * 1000

		switch unit {
		case "m":
			if num < minutes {
				return true, nil
			}
		case "s":
			if num < seconds {
				return true, nil
			}
		case "ms":
			if num < us {
				return true, nil
			}
		}
	}

	return false, nil
}

// validateTimeout receives a timeout string and a boolean indicating whether a bypass
// has been used, and returns the appropriate response.
func validateTimeout(timeout string, bypass bool) admission.Response {
	if timeout != "" {
		if !validateTimeoutString(timeout) {
			return admission.Denied("Timeout annotation is not valid. You need to use a string of number + time unit.")
		}
	}

	res, err := validateTimeoutRange(timeout)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	if !bypass && !res {
		return admission.Denied(fmt.Sprint("Timeout annotation value is invalid. The maximum seconds timeout is $qs", os.Getenv("secondsTimeout")))
	}

	return admission.Allowed("Route is valid")
}

func (r *RouteValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	log := r.Log.WithValues("webhook", "Route Webhook", "Name", req.Name)

	route := routev1.Route{}
	log.Info("webhook request received")
	if err := r.Decoder.Decode(req, &route); err != nil {
		log.Error(err, "could not decode route object")
		return admission.Errored(http.StatusInternalServerError, err)
	}

	namespace := corev1.Namespace{}
	log.Info("webhook request received")
	if err := r.Client.Get(ctx, types.NamespacedName{Name: route.Namespace}, &namespace); err != nil {
		log.Error(err, "could not get namespace")
		return admission.Errored(http.StatusInternalServerError, err)
	}

	if timeout, ok := route.Annotations[timeoutAnnotation]; ok {
		bypass := false
		v, ok := namespace.Labels[adminBypassTimeoutLabel]
		if ok && v == "true" {
			bypass = true
		}
		return validateTimeout(timeout, bypass)
	}

	return admission.Allowed("No timeout on route")
}
