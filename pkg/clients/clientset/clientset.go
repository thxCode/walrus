// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package clientset

import (
	"fmt"
	"net/http"

	admissionv1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/admission/v1"
	admissionregistrationv1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/admissionregistration/v1"
	apiextensionsv1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/apiextensions/v1"
	apiregistrationv1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/apiregistration/v1"
	appsv1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/apps/v1"
	authenticationv1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/authentication/v1"
	authorizationv1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/authorization/v1"
	autoscalingv1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/autoscaling/v1"
	autoscalingv2 "github.com/seal-io/walrus/pkg/clients/clientset/typed/autoscaling/v2"
	batchv1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/batch/v1"
	certificatesv1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/certificates/v1"
	coordinationv1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/coordination/v1"
	corev1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/core/v1"
	discoveryv1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/discovery/v1"
	eventsv1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/events/v1"
	rbacv1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/rbac/v1"
	schedulingv1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/scheduling/v1"
	storagev1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/storage/v1"
	walrusv1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/walrus/v1"
	walruscorev1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/walruscore/v1"
	discovery "k8s.io/client-go/discovery"
	rest "k8s.io/client-go/rest"
	flowcontrol "k8s.io/client-go/util/flowcontrol"
)

type Interface interface {
	Discovery() discovery.DiscoveryInterface
	WalruscoreV1() walruscorev1.WalruscoreV1Interface
	WalrusV1() walrusv1.WalrusV1Interface
	AdmissionV1() admissionv1.AdmissionV1Interface
	AdmissionregistrationV1() admissionregistrationv1.AdmissionregistrationV1Interface
	AppsV1() appsv1.AppsV1Interface
	AuthenticationV1() authenticationv1.AuthenticationV1Interface
	AuthorizationV1() authorizationv1.AuthorizationV1Interface
	AutoscalingV1() autoscalingv1.AutoscalingV1Interface
	AutoscalingV2() autoscalingv2.AutoscalingV2Interface
	BatchV1() batchv1.BatchV1Interface
	CertificatesV1() certificatesv1.CertificatesV1Interface
	CoordinationV1() coordinationv1.CoordinationV1Interface
	CoreV1() corev1.CoreV1Interface
	DiscoveryV1() discoveryv1.DiscoveryV1Interface
	EventsV1() eventsv1.EventsV1Interface
	RbacV1() rbacv1.RbacV1Interface
	SchedulingV1() schedulingv1.SchedulingV1Interface
	StorageV1() storagev1.StorageV1Interface
	ApiextensionsV1() apiextensionsv1.ApiextensionsV1Interface
	ApiregistrationV1() apiregistrationv1.ApiregistrationV1Interface
}

// Clientset contains the clients for groups.
type Clientset struct {
	*discovery.DiscoveryClient
	walruscoreV1            *walruscorev1.WalruscoreV1Client
	walrusV1                *walrusv1.WalrusV1Client
	admissionV1             *admissionv1.AdmissionV1Client
	admissionregistrationV1 *admissionregistrationv1.AdmissionregistrationV1Client
	appsV1                  *appsv1.AppsV1Client
	authenticationV1        *authenticationv1.AuthenticationV1Client
	authorizationV1         *authorizationv1.AuthorizationV1Client
	autoscalingV1           *autoscalingv1.AutoscalingV1Client
	autoscalingV2           *autoscalingv2.AutoscalingV2Client
	batchV1                 *batchv1.BatchV1Client
	certificatesV1          *certificatesv1.CertificatesV1Client
	coordinationV1          *coordinationv1.CoordinationV1Client
	coreV1                  *corev1.CoreV1Client
	discoveryV1             *discoveryv1.DiscoveryV1Client
	eventsV1                *eventsv1.EventsV1Client
	rbacV1                  *rbacv1.RbacV1Client
	schedulingV1            *schedulingv1.SchedulingV1Client
	storageV1               *storagev1.StorageV1Client
	apiextensionsV1         *apiextensionsv1.ApiextensionsV1Client
	apiregistrationV1       *apiregistrationv1.ApiregistrationV1Client
}

// WalruscoreV1 retrieves the WalruscoreV1Client
func (c *Clientset) WalruscoreV1() walruscorev1.WalruscoreV1Interface {
	return c.walruscoreV1
}

// WalrusV1 retrieves the WalrusV1Client
func (c *Clientset) WalrusV1() walrusv1.WalrusV1Interface {
	return c.walrusV1
}

// AdmissionV1 retrieves the AdmissionV1Client
func (c *Clientset) AdmissionV1() admissionv1.AdmissionV1Interface {
	return c.admissionV1
}

// AdmissionregistrationV1 retrieves the AdmissionregistrationV1Client
func (c *Clientset) AdmissionregistrationV1() admissionregistrationv1.AdmissionregistrationV1Interface {
	return c.admissionregistrationV1
}

// AppsV1 retrieves the AppsV1Client
func (c *Clientset) AppsV1() appsv1.AppsV1Interface {
	return c.appsV1
}

// AuthenticationV1 retrieves the AuthenticationV1Client
func (c *Clientset) AuthenticationV1() authenticationv1.AuthenticationV1Interface {
	return c.authenticationV1
}

// AuthorizationV1 retrieves the AuthorizationV1Client
func (c *Clientset) AuthorizationV1() authorizationv1.AuthorizationV1Interface {
	return c.authorizationV1
}

// AutoscalingV1 retrieves the AutoscalingV1Client
func (c *Clientset) AutoscalingV1() autoscalingv1.AutoscalingV1Interface {
	return c.autoscalingV1
}

// AutoscalingV2 retrieves the AutoscalingV2Client
func (c *Clientset) AutoscalingV2() autoscalingv2.AutoscalingV2Interface {
	return c.autoscalingV2
}

// BatchV1 retrieves the BatchV1Client
func (c *Clientset) BatchV1() batchv1.BatchV1Interface {
	return c.batchV1
}

// CertificatesV1 retrieves the CertificatesV1Client
func (c *Clientset) CertificatesV1() certificatesv1.CertificatesV1Interface {
	return c.certificatesV1
}

// CoordinationV1 retrieves the CoordinationV1Client
func (c *Clientset) CoordinationV1() coordinationv1.CoordinationV1Interface {
	return c.coordinationV1
}

// CoreV1 retrieves the CoreV1Client
func (c *Clientset) CoreV1() corev1.CoreV1Interface {
	return c.coreV1
}

// DiscoveryV1 retrieves the DiscoveryV1Client
func (c *Clientset) DiscoveryV1() discoveryv1.DiscoveryV1Interface {
	return c.discoveryV1
}

// EventsV1 retrieves the EventsV1Client
func (c *Clientset) EventsV1() eventsv1.EventsV1Interface {
	return c.eventsV1
}

// RbacV1 retrieves the RbacV1Client
func (c *Clientset) RbacV1() rbacv1.RbacV1Interface {
	return c.rbacV1
}

// SchedulingV1 retrieves the SchedulingV1Client
func (c *Clientset) SchedulingV1() schedulingv1.SchedulingV1Interface {
	return c.schedulingV1
}

// StorageV1 retrieves the StorageV1Client
func (c *Clientset) StorageV1() storagev1.StorageV1Interface {
	return c.storageV1
}

// ApiextensionsV1 retrieves the ApiextensionsV1Client
func (c *Clientset) ApiextensionsV1() apiextensionsv1.ApiextensionsV1Interface {
	return c.apiextensionsV1
}

// ApiregistrationV1 retrieves the ApiregistrationV1Client
func (c *Clientset) ApiregistrationV1() apiregistrationv1.ApiregistrationV1Interface {
	return c.apiregistrationV1
}

// Discovery retrieves the DiscoveryClient
func (c *Clientset) Discovery() discovery.DiscoveryInterface {
	if c == nil {
		return nil
	}
	return c.DiscoveryClient
}

// NewForConfig creates a new Clientset for the given config.
// If config's RateLimiter is not set and QPS and Burst are acceptable,
// NewForConfig will generate a rate-limiter in configShallowCopy.
// NewForConfig is equivalent to NewForConfigAndClient(c, httpClient),
// where httpClient was generated with rest.HTTPClientFor(c).
func NewForConfig(c *rest.Config) (*Clientset, error) {
	configShallowCopy := *c

	if configShallowCopy.UserAgent == "" {
		configShallowCopy.UserAgent = rest.DefaultKubernetesUserAgent()
	}

	// share the transport between all clients
	httpClient, err := rest.HTTPClientFor(&configShallowCopy)
	if err != nil {
		return nil, err
	}

	return NewForConfigAndClient(&configShallowCopy, httpClient)
}

// NewForConfigAndClient creates a new Clientset for the given config and http client.
// Note the http client provided takes precedence over the configured transport values.
// If config's RateLimiter is not set and QPS and Burst are acceptable,
// NewForConfigAndClient will generate a rate-limiter in configShallowCopy.
func NewForConfigAndClient(c *rest.Config, httpClient *http.Client) (*Clientset, error) {
	configShallowCopy := *c
	if configShallowCopy.RateLimiter == nil && configShallowCopy.QPS > 0 {
		if configShallowCopy.Burst <= 0 {
			return nil, fmt.Errorf("burst is required to be greater than 0 when RateLimiter is not set and QPS is set to greater than 0")
		}
		configShallowCopy.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(configShallowCopy.QPS, configShallowCopy.Burst)
	}

	var cs Clientset
	var err error
	cs.walruscoreV1, err = walruscorev1.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}
	cs.walrusV1, err = walrusv1.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}
	cs.admissionV1, err = admissionv1.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}
	cs.admissionregistrationV1, err = admissionregistrationv1.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}
	cs.appsV1, err = appsv1.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}
	cs.authenticationV1, err = authenticationv1.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}
	cs.authorizationV1, err = authorizationv1.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}
	cs.autoscalingV1, err = autoscalingv1.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}
	cs.autoscalingV2, err = autoscalingv2.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}
	cs.batchV1, err = batchv1.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}
	cs.certificatesV1, err = certificatesv1.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}
	cs.coordinationV1, err = coordinationv1.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}
	cs.coreV1, err = corev1.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}
	cs.discoveryV1, err = discoveryv1.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}
	cs.eventsV1, err = eventsv1.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}
	cs.rbacV1, err = rbacv1.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}
	cs.schedulingV1, err = schedulingv1.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}
	cs.storageV1, err = storagev1.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}
	cs.apiextensionsV1, err = apiextensionsv1.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}
	cs.apiregistrationV1, err = apiregistrationv1.NewForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}

	cs.DiscoveryClient, err = discovery.NewDiscoveryClientForConfigAndClient(&configShallowCopy, httpClient)
	if err != nil {
		return nil, err
	}
	return &cs, nil
}

// NewForConfigOrDie creates a new Clientset for the given config and
// panics if there is an error in the config.
func NewForConfigOrDie(c *rest.Config) *Clientset {
	cs, err := NewForConfig(c)
	if err != nil {
		panic(err)
	}
	return cs
}

// New creates a new Clientset for the given RESTClient.
func New(c rest.Interface) *Clientset {
	var cs Clientset
	cs.walruscoreV1 = walruscorev1.New(c)
	cs.walrusV1 = walrusv1.New(c)
	cs.admissionV1 = admissionv1.New(c)
	cs.admissionregistrationV1 = admissionregistrationv1.New(c)
	cs.appsV1 = appsv1.New(c)
	cs.authenticationV1 = authenticationv1.New(c)
	cs.authorizationV1 = authorizationv1.New(c)
	cs.autoscalingV1 = autoscalingv1.New(c)
	cs.autoscalingV2 = autoscalingv2.New(c)
	cs.batchV1 = batchv1.New(c)
	cs.certificatesV1 = certificatesv1.New(c)
	cs.coordinationV1 = coordinationv1.New(c)
	cs.coreV1 = corev1.New(c)
	cs.discoveryV1 = discoveryv1.New(c)
	cs.eventsV1 = eventsv1.New(c)
	cs.rbacV1 = rbacv1.New(c)
	cs.schedulingV1 = schedulingv1.New(c)
	cs.storageV1 = storagev1.New(c)
	cs.apiextensionsV1 = apiextensionsv1.New(c)
	cs.apiregistrationV1 = apiregistrationv1.New(c)

	cs.DiscoveryClient = discovery.NewDiscoveryClient(c)
	return &cs
}
