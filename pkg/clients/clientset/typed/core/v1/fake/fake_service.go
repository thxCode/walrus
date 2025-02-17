// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package fake

import (
	"context"
	json "encoding/json"
	"fmt"

	corev1 "github.com/seal-io/walrus/pkg/clients/applyconfiguration/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeServices implements ServiceInterface
type FakeServices struct {
	Fake *FakeCoreV1
	ns   string
}

var servicesResource = v1.SchemeGroupVersion.WithResource("services")

var servicesKind = v1.SchemeGroupVersion.WithKind("Service")

// Get takes name of the service, and returns the corresponding service object, and an error if there is any.
func (c *FakeServices) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.Service, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(servicesResource, c.ns, name), &v1.Service{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.Service), err
}

// List takes label and field selectors, and returns the list of Services that match those selectors.
func (c *FakeServices) List(ctx context.Context, opts metav1.ListOptions) (result *v1.ServiceList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(servicesResource, servicesKind, c.ns, opts), &v1.ServiceList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.ServiceList{ListMeta: obj.(*v1.ServiceList).ListMeta}
	for _, item := range obj.(*v1.ServiceList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested services.
func (c *FakeServices) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(servicesResource, c.ns, opts))

}

// Create takes the representation of a service and creates it.  Returns the server's representation of the service, and an error, if there is any.
func (c *FakeServices) Create(ctx context.Context, service *v1.Service, opts metav1.CreateOptions) (result *v1.Service, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(servicesResource, c.ns, service), &v1.Service{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.Service), err
}

// Update takes the representation of a service and updates it. Returns the server's representation of the service, and an error, if there is any.
func (c *FakeServices) Update(ctx context.Context, service *v1.Service, opts metav1.UpdateOptions) (result *v1.Service, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(servicesResource, c.ns, service), &v1.Service{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.Service), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeServices) UpdateStatus(ctx context.Context, service *v1.Service, opts metav1.UpdateOptions) (*v1.Service, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(servicesResource, "status", c.ns, service), &v1.Service{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.Service), err
}

// Delete takes name of the service and deletes it. Returns an error if one occurs.
func (c *FakeServices) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(servicesResource, c.ns, name, opts), &v1.Service{})

	return err
}

// Patch applies the patch and returns the patched service.
func (c *FakeServices) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.Service, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(servicesResource, c.ns, name, pt, data, subresources...), &v1.Service{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.Service), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied service.
func (c *FakeServices) Apply(ctx context.Context, service *corev1.ServiceApplyConfiguration, opts metav1.ApplyOptions) (result *v1.Service, err error) {
	if service == nil {
		return nil, fmt.Errorf("service provided to Apply must not be nil")
	}
	data, err := json.Marshal(service)
	if err != nil {
		return nil, err
	}
	name := service.Name
	if name == nil {
		return nil, fmt.Errorf("service.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(servicesResource, c.ns, *name, types.ApplyPatchType, data), &v1.Service{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.Service), err
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *FakeServices) ApplyStatus(ctx context.Context, service *corev1.ServiceApplyConfiguration, opts metav1.ApplyOptions) (result *v1.Service, err error) {
	if service == nil {
		return nil, fmt.Errorf("service provided to Apply must not be nil")
	}
	data, err := json.Marshal(service)
	if err != nil {
		return nil, err
	}
	name := service.Name
	if name == nil {
		return nil, fmt.Errorf("service.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(servicesResource, c.ns, *name, types.ApplyPatchType, data, "status"), &v1.Service{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.Service), err
}
