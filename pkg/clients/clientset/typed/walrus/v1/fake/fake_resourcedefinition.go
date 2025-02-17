// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package fake

import (
	"context"
	json "encoding/json"
	"fmt"

	v1 "github.com/seal-io/walrus/pkg/apis/walrus/v1"
	walrusv1 "github.com/seal-io/walrus/pkg/clients/applyconfiguration/walrus/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeResourceDefinitions implements ResourceDefinitionInterface
type FakeResourceDefinitions struct {
	Fake *FakeWalrusV1
	ns   string
}

var resourcedefinitionsResource = v1.SchemeGroupVersion.WithResource("resourcedefinitions")

var resourcedefinitionsKind = v1.SchemeGroupVersion.WithKind("ResourceDefinition")

// Get takes name of the resourceDefinition, and returns the corresponding resourceDefinition object, and an error if there is any.
func (c *FakeResourceDefinitions) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.ResourceDefinition, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(resourcedefinitionsResource, c.ns, name), &v1.ResourceDefinition{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.ResourceDefinition), err
}

// List takes label and field selectors, and returns the list of ResourceDefinitions that match those selectors.
func (c *FakeResourceDefinitions) List(ctx context.Context, opts metav1.ListOptions) (result *v1.ResourceDefinitionList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(resourcedefinitionsResource, resourcedefinitionsKind, c.ns, opts), &v1.ResourceDefinitionList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.ResourceDefinitionList{ListMeta: obj.(*v1.ResourceDefinitionList).ListMeta}
	for _, item := range obj.(*v1.ResourceDefinitionList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested resourceDefinitions.
func (c *FakeResourceDefinitions) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(resourcedefinitionsResource, c.ns, opts))

}

// Create takes the representation of a resourceDefinition and creates it.  Returns the server's representation of the resourceDefinition, and an error, if there is any.
func (c *FakeResourceDefinitions) Create(ctx context.Context, resourceDefinition *v1.ResourceDefinition, opts metav1.CreateOptions) (result *v1.ResourceDefinition, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(resourcedefinitionsResource, c.ns, resourceDefinition), &v1.ResourceDefinition{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.ResourceDefinition), err
}

// Update takes the representation of a resourceDefinition and updates it. Returns the server's representation of the resourceDefinition, and an error, if there is any.
func (c *FakeResourceDefinitions) Update(ctx context.Context, resourceDefinition *v1.ResourceDefinition, opts metav1.UpdateOptions) (result *v1.ResourceDefinition, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(resourcedefinitionsResource, c.ns, resourceDefinition), &v1.ResourceDefinition{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.ResourceDefinition), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeResourceDefinitions) UpdateStatus(ctx context.Context, resourceDefinition *v1.ResourceDefinition, opts metav1.UpdateOptions) (*v1.ResourceDefinition, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(resourcedefinitionsResource, "status", c.ns, resourceDefinition), &v1.ResourceDefinition{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.ResourceDefinition), err
}

// Delete takes name of the resourceDefinition and deletes it. Returns an error if one occurs.
func (c *FakeResourceDefinitions) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(resourcedefinitionsResource, c.ns, name, opts), &v1.ResourceDefinition{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeResourceDefinitions) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(resourcedefinitionsResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1.ResourceDefinitionList{})
	return err
}

// Patch applies the patch and returns the patched resourceDefinition.
func (c *FakeResourceDefinitions) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.ResourceDefinition, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(resourcedefinitionsResource, c.ns, name, pt, data, subresources...), &v1.ResourceDefinition{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.ResourceDefinition), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied resourceDefinition.
func (c *FakeResourceDefinitions) Apply(ctx context.Context, resourceDefinition *walrusv1.ResourceDefinitionApplyConfiguration, opts metav1.ApplyOptions) (result *v1.ResourceDefinition, err error) {
	if resourceDefinition == nil {
		return nil, fmt.Errorf("resourceDefinition provided to Apply must not be nil")
	}
	data, err := json.Marshal(resourceDefinition)
	if err != nil {
		return nil, err
	}
	name := resourceDefinition.Name
	if name == nil {
		return nil, fmt.Errorf("resourceDefinition.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(resourcedefinitionsResource, c.ns, *name, types.ApplyPatchType, data), &v1.ResourceDefinition{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.ResourceDefinition), err
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *FakeResourceDefinitions) ApplyStatus(ctx context.Context, resourceDefinition *walrusv1.ResourceDefinitionApplyConfiguration, opts metav1.ApplyOptions) (result *v1.ResourceDefinition, err error) {
	if resourceDefinition == nil {
		return nil, fmt.Errorf("resourceDefinition provided to Apply must not be nil")
	}
	data, err := json.Marshal(resourceDefinition)
	if err != nil {
		return nil, err
	}
	name := resourceDefinition.Name
	if name == nil {
		return nil, fmt.Errorf("resourceDefinition.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(resourcedefinitionsResource, c.ns, *name, types.ApplyPatchType, data, "status"), &v1.ResourceDefinition{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.ResourceDefinition), err
}
