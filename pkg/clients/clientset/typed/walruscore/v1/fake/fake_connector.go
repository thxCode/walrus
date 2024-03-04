// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package fake

import (
	"context"
	json "encoding/json"
	"fmt"

	v1 "github.com/seal-io/walrus/pkg/apis/walruscore/v1"
	walruscorev1 "github.com/seal-io/walrus/pkg/clients/applyconfiguration/walruscore/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeConnectors implements ConnectorInterface
type FakeConnectors struct {
	Fake *FakeWalruscoreV1
	ns   string
}

var connectorsResource = v1.SchemeGroupVersion.WithResource("connectors")

var connectorsKind = v1.SchemeGroupVersion.WithKind("Connector")

// Get takes name of the connector, and returns the corresponding connector object, and an error if there is any.
func (c *FakeConnectors) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.Connector, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(connectorsResource, c.ns, name), &v1.Connector{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.Connector), err
}

// List takes label and field selectors, and returns the list of Connectors that match those selectors.
func (c *FakeConnectors) List(ctx context.Context, opts metav1.ListOptions) (result *v1.ConnectorList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(connectorsResource, connectorsKind, c.ns, opts), &v1.ConnectorList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.ConnectorList{ListMeta: obj.(*v1.ConnectorList).ListMeta}
	for _, item := range obj.(*v1.ConnectorList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested connectors.
func (c *FakeConnectors) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(connectorsResource, c.ns, opts))

}

// Create takes the representation of a connector and creates it.  Returns the server's representation of the connector, and an error, if there is any.
func (c *FakeConnectors) Create(ctx context.Context, connector *v1.Connector, opts metav1.CreateOptions) (result *v1.Connector, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(connectorsResource, c.ns, connector), &v1.Connector{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.Connector), err
}

// Update takes the representation of a connector and updates it. Returns the server's representation of the connector, and an error, if there is any.
func (c *FakeConnectors) Update(ctx context.Context, connector *v1.Connector, opts metav1.UpdateOptions) (result *v1.Connector, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(connectorsResource, c.ns, connector), &v1.Connector{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.Connector), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeConnectors) UpdateStatus(ctx context.Context, connector *v1.Connector, opts metav1.UpdateOptions) (*v1.Connector, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(connectorsResource, "status", c.ns, connector), &v1.Connector{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.Connector), err
}

// Delete takes name of the connector and deletes it. Returns an error if one occurs.
func (c *FakeConnectors) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(connectorsResource, c.ns, name, opts), &v1.Connector{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeConnectors) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(connectorsResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1.ConnectorList{})
	return err
}

// Patch applies the patch and returns the patched connector.
func (c *FakeConnectors) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.Connector, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(connectorsResource, c.ns, name, pt, data, subresources...), &v1.Connector{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.Connector), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied connector.
func (c *FakeConnectors) Apply(ctx context.Context, connector *walruscorev1.ConnectorApplyConfiguration, opts metav1.ApplyOptions) (result *v1.Connector, err error) {
	if connector == nil {
		return nil, fmt.Errorf("connector provided to Apply must not be nil")
	}
	data, err := json.Marshal(connector)
	if err != nil {
		return nil, err
	}
	name := connector.Name
	if name == nil {
		return nil, fmt.Errorf("connector.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(connectorsResource, c.ns, *name, types.ApplyPatchType, data), &v1.Connector{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.Connector), err
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *FakeConnectors) ApplyStatus(ctx context.Context, connector *walruscorev1.ConnectorApplyConfiguration, opts metav1.ApplyOptions) (result *v1.Connector, err error) {
	if connector == nil {
		return nil, fmt.Errorf("connector provided to Apply must not be nil")
	}
	data, err := json.Marshal(connector)
	if err != nil {
		return nil, err
	}
	name := connector.Name
	if name == nil {
		return nil, fmt.Errorf("connector.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(connectorsResource, c.ns, *name, types.ApplyPatchType, data, "status"), &v1.Connector{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.Connector), err
}
