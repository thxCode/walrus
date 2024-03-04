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

// FakePodTemplates implements PodTemplateInterface
type FakePodTemplates struct {
	Fake *FakeCoreV1
	ns   string
}

var podtemplatesResource = v1.SchemeGroupVersion.WithResource("podtemplates")

var podtemplatesKind = v1.SchemeGroupVersion.WithKind("PodTemplate")

// Get takes name of the podTemplate, and returns the corresponding podTemplate object, and an error if there is any.
func (c *FakePodTemplates) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.PodTemplate, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(podtemplatesResource, c.ns, name), &v1.PodTemplate{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.PodTemplate), err
}

// List takes label and field selectors, and returns the list of PodTemplates that match those selectors.
func (c *FakePodTemplates) List(ctx context.Context, opts metav1.ListOptions) (result *v1.PodTemplateList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(podtemplatesResource, podtemplatesKind, c.ns, opts), &v1.PodTemplateList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.PodTemplateList{ListMeta: obj.(*v1.PodTemplateList).ListMeta}
	for _, item := range obj.(*v1.PodTemplateList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested podTemplates.
func (c *FakePodTemplates) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(podtemplatesResource, c.ns, opts))

}

// Create takes the representation of a podTemplate and creates it.  Returns the server's representation of the podTemplate, and an error, if there is any.
func (c *FakePodTemplates) Create(ctx context.Context, podTemplate *v1.PodTemplate, opts metav1.CreateOptions) (result *v1.PodTemplate, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(podtemplatesResource, c.ns, podTemplate), &v1.PodTemplate{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.PodTemplate), err
}

// Update takes the representation of a podTemplate and updates it. Returns the server's representation of the podTemplate, and an error, if there is any.
func (c *FakePodTemplates) Update(ctx context.Context, podTemplate *v1.PodTemplate, opts metav1.UpdateOptions) (result *v1.PodTemplate, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(podtemplatesResource, c.ns, podTemplate), &v1.PodTemplate{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.PodTemplate), err
}

// Delete takes name of the podTemplate and deletes it. Returns an error if one occurs.
func (c *FakePodTemplates) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(podtemplatesResource, c.ns, name, opts), &v1.PodTemplate{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakePodTemplates) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(podtemplatesResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1.PodTemplateList{})
	return err
}

// Patch applies the patch and returns the patched podTemplate.
func (c *FakePodTemplates) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.PodTemplate, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(podtemplatesResource, c.ns, name, pt, data, subresources...), &v1.PodTemplate{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.PodTemplate), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied podTemplate.
func (c *FakePodTemplates) Apply(ctx context.Context, podTemplate *corev1.PodTemplateApplyConfiguration, opts metav1.ApplyOptions) (result *v1.PodTemplate, err error) {
	if podTemplate == nil {
		return nil, fmt.Errorf("podTemplate provided to Apply must not be nil")
	}
	data, err := json.Marshal(podTemplate)
	if err != nil {
		return nil, err
	}
	name := podTemplate.Name
	if name == nil {
		return nil, fmt.Errorf("podTemplate.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(podtemplatesResource, c.ns, *name, types.ApplyPatchType, data), &v1.PodTemplate{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.PodTemplate), err
}
