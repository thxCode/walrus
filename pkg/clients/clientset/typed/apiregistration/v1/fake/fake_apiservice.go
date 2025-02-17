// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package fake

import (
	"context"
	json "encoding/json"
	"fmt"

	apiregistrationv1 "github.com/seal-io/walrus/pkg/clients/applyconfiguration/apiregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
	v1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
)

// FakeAPIServices implements APIServiceInterface
type FakeAPIServices struct {
	Fake *FakeApiregistrationV1
}

var apiservicesResource = v1.SchemeGroupVersion.WithResource("apiservices")

var apiservicesKind = v1.SchemeGroupVersion.WithKind("APIService")

// Get takes name of the aPIService, and returns the corresponding aPIService object, and an error if there is any.
func (c *FakeAPIServices) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.APIService, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(apiservicesResource, name), &v1.APIService{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.APIService), err
}

// List takes label and field selectors, and returns the list of APIServices that match those selectors.
func (c *FakeAPIServices) List(ctx context.Context, opts metav1.ListOptions) (result *v1.APIServiceList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(apiservicesResource, apiservicesKind, opts), &v1.APIServiceList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.APIServiceList{ListMeta: obj.(*v1.APIServiceList).ListMeta}
	for _, item := range obj.(*v1.APIServiceList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested aPIServices.
func (c *FakeAPIServices) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(apiservicesResource, opts))
}

// Create takes the representation of a aPIService and creates it.  Returns the server's representation of the aPIService, and an error, if there is any.
func (c *FakeAPIServices) Create(ctx context.Context, aPIService *v1.APIService, opts metav1.CreateOptions) (result *v1.APIService, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(apiservicesResource, aPIService), &v1.APIService{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.APIService), err
}

// Update takes the representation of a aPIService and updates it. Returns the server's representation of the aPIService, and an error, if there is any.
func (c *FakeAPIServices) Update(ctx context.Context, aPIService *v1.APIService, opts metav1.UpdateOptions) (result *v1.APIService, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(apiservicesResource, aPIService), &v1.APIService{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.APIService), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeAPIServices) UpdateStatus(ctx context.Context, aPIService *v1.APIService, opts metav1.UpdateOptions) (*v1.APIService, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(apiservicesResource, "status", aPIService), &v1.APIService{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.APIService), err
}

// Delete takes name of the aPIService and deletes it. Returns an error if one occurs.
func (c *FakeAPIServices) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(apiservicesResource, name, opts), &v1.APIService{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeAPIServices) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(apiservicesResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1.APIServiceList{})
	return err
}

// Patch applies the patch and returns the patched aPIService.
func (c *FakeAPIServices) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.APIService, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(apiservicesResource, name, pt, data, subresources...), &v1.APIService{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.APIService), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied aPIService.
func (c *FakeAPIServices) Apply(ctx context.Context, aPIService *apiregistrationv1.APIServiceApplyConfiguration, opts metav1.ApplyOptions) (result *v1.APIService, err error) {
	if aPIService == nil {
		return nil, fmt.Errorf("aPIService provided to Apply must not be nil")
	}
	data, err := json.Marshal(aPIService)
	if err != nil {
		return nil, err
	}
	name := aPIService.Name
	if name == nil {
		return nil, fmt.Errorf("aPIService.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(apiservicesResource, *name, types.ApplyPatchType, data), &v1.APIService{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.APIService), err
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *FakeAPIServices) ApplyStatus(ctx context.Context, aPIService *apiregistrationv1.APIServiceApplyConfiguration, opts metav1.ApplyOptions) (result *v1.APIService, err error) {
	if aPIService == nil {
		return nil, fmt.Errorf("aPIService provided to Apply must not be nil")
	}
	data, err := json.Marshal(aPIService)
	if err != nil {
		return nil, err
	}
	name := aPIService.Name
	if name == nil {
		return nil, fmt.Errorf("aPIService.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(apiservicesResource, *name, types.ApplyPatchType, data, "status"), &v1.APIService{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.APIService), err
}
