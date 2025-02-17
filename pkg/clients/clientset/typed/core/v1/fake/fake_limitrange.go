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

// FakeLimitRanges implements LimitRangeInterface
type FakeLimitRanges struct {
	Fake *FakeCoreV1
	ns   string
}

var limitrangesResource = v1.SchemeGroupVersion.WithResource("limitranges")

var limitrangesKind = v1.SchemeGroupVersion.WithKind("LimitRange")

// Get takes name of the limitRange, and returns the corresponding limitRange object, and an error if there is any.
func (c *FakeLimitRanges) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.LimitRange, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(limitrangesResource, c.ns, name), &v1.LimitRange{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.LimitRange), err
}

// List takes label and field selectors, and returns the list of LimitRanges that match those selectors.
func (c *FakeLimitRanges) List(ctx context.Context, opts metav1.ListOptions) (result *v1.LimitRangeList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(limitrangesResource, limitrangesKind, c.ns, opts), &v1.LimitRangeList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.LimitRangeList{ListMeta: obj.(*v1.LimitRangeList).ListMeta}
	for _, item := range obj.(*v1.LimitRangeList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested limitRanges.
func (c *FakeLimitRanges) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(limitrangesResource, c.ns, opts))

}

// Create takes the representation of a limitRange and creates it.  Returns the server's representation of the limitRange, and an error, if there is any.
func (c *FakeLimitRanges) Create(ctx context.Context, limitRange *v1.LimitRange, opts metav1.CreateOptions) (result *v1.LimitRange, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(limitrangesResource, c.ns, limitRange), &v1.LimitRange{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.LimitRange), err
}

// Update takes the representation of a limitRange and updates it. Returns the server's representation of the limitRange, and an error, if there is any.
func (c *FakeLimitRanges) Update(ctx context.Context, limitRange *v1.LimitRange, opts metav1.UpdateOptions) (result *v1.LimitRange, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(limitrangesResource, c.ns, limitRange), &v1.LimitRange{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.LimitRange), err
}

// Delete takes name of the limitRange and deletes it. Returns an error if one occurs.
func (c *FakeLimitRanges) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(limitrangesResource, c.ns, name, opts), &v1.LimitRange{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeLimitRanges) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(limitrangesResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1.LimitRangeList{})
	return err
}

// Patch applies the patch and returns the patched limitRange.
func (c *FakeLimitRanges) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.LimitRange, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(limitrangesResource, c.ns, name, pt, data, subresources...), &v1.LimitRange{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.LimitRange), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied limitRange.
func (c *FakeLimitRanges) Apply(ctx context.Context, limitRange *corev1.LimitRangeApplyConfiguration, opts metav1.ApplyOptions) (result *v1.LimitRange, err error) {
	if limitRange == nil {
		return nil, fmt.Errorf("limitRange provided to Apply must not be nil")
	}
	data, err := json.Marshal(limitRange)
	if err != nil {
		return nil, err
	}
	name := limitRange.Name
	if name == nil {
		return nil, fmt.Errorf("limitRange.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(limitrangesResource, c.ns, *name, types.ApplyPatchType, data), &v1.LimitRange{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.LimitRange), err
}
