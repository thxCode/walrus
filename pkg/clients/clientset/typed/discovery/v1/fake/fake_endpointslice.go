// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package fake

import (
	"context"
	json "encoding/json"
	"fmt"

	discoveryv1 "github.com/seal-io/walrus/pkg/clients/applyconfiguration/discovery/v1"
	v1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeEndpointSlices implements EndpointSliceInterface
type FakeEndpointSlices struct {
	Fake *FakeDiscoveryV1
	ns   string
}

var endpointslicesResource = v1.SchemeGroupVersion.WithResource("endpointslices")

var endpointslicesKind = v1.SchemeGroupVersion.WithKind("EndpointSlice")

// Get takes name of the endpointSlice, and returns the corresponding endpointSlice object, and an error if there is any.
func (c *FakeEndpointSlices) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.EndpointSlice, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(endpointslicesResource, c.ns, name), &v1.EndpointSlice{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.EndpointSlice), err
}

// List takes label and field selectors, and returns the list of EndpointSlices that match those selectors.
func (c *FakeEndpointSlices) List(ctx context.Context, opts metav1.ListOptions) (result *v1.EndpointSliceList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(endpointslicesResource, endpointslicesKind, c.ns, opts), &v1.EndpointSliceList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.EndpointSliceList{ListMeta: obj.(*v1.EndpointSliceList).ListMeta}
	for _, item := range obj.(*v1.EndpointSliceList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested endpointSlices.
func (c *FakeEndpointSlices) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(endpointslicesResource, c.ns, opts))

}

// Create takes the representation of a endpointSlice and creates it.  Returns the server's representation of the endpointSlice, and an error, if there is any.
func (c *FakeEndpointSlices) Create(ctx context.Context, endpointSlice *v1.EndpointSlice, opts metav1.CreateOptions) (result *v1.EndpointSlice, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(endpointslicesResource, c.ns, endpointSlice), &v1.EndpointSlice{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.EndpointSlice), err
}

// Update takes the representation of a endpointSlice and updates it. Returns the server's representation of the endpointSlice, and an error, if there is any.
func (c *FakeEndpointSlices) Update(ctx context.Context, endpointSlice *v1.EndpointSlice, opts metav1.UpdateOptions) (result *v1.EndpointSlice, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(endpointslicesResource, c.ns, endpointSlice), &v1.EndpointSlice{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.EndpointSlice), err
}

// Delete takes name of the endpointSlice and deletes it. Returns an error if one occurs.
func (c *FakeEndpointSlices) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(endpointslicesResource, c.ns, name, opts), &v1.EndpointSlice{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeEndpointSlices) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(endpointslicesResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1.EndpointSliceList{})
	return err
}

// Patch applies the patch and returns the patched endpointSlice.
func (c *FakeEndpointSlices) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.EndpointSlice, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(endpointslicesResource, c.ns, name, pt, data, subresources...), &v1.EndpointSlice{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.EndpointSlice), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied endpointSlice.
func (c *FakeEndpointSlices) Apply(ctx context.Context, endpointSlice *discoveryv1.EndpointSliceApplyConfiguration, opts metav1.ApplyOptions) (result *v1.EndpointSlice, err error) {
	if endpointSlice == nil {
		return nil, fmt.Errorf("endpointSlice provided to Apply must not be nil")
	}
	data, err := json.Marshal(endpointSlice)
	if err != nil {
		return nil, err
	}
	name := endpointSlice.Name
	if name == nil {
		return nil, fmt.Errorf("endpointSlice.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(endpointslicesResource, c.ns, *name, types.ApplyPatchType, data), &v1.EndpointSlice{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.EndpointSlice), err
}
