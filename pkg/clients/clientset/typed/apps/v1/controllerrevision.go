// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

import (
	"context"
	json "encoding/json"
	"fmt"
	"time"

	appsv1 "github.com/seal-io/walrus/pkg/clients/applyconfiguration/apps/v1"
	scheme "github.com/seal-io/walrus/pkg/clients/clientset/scheme"
	v1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// ControllerRevisionsGetter has a method to return a ControllerRevisionInterface.
// A group's client should implement this interface.
type ControllerRevisionsGetter interface {
	ControllerRevisions(namespace string) ControllerRevisionInterface
}

// ControllerRevisionInterface has methods to work with ControllerRevision resources.
type ControllerRevisionInterface interface {
	Create(ctx context.Context, controllerRevision *v1.ControllerRevision, opts metav1.CreateOptions) (*v1.ControllerRevision, error)
	Update(ctx context.Context, controllerRevision *v1.ControllerRevision, opts metav1.UpdateOptions) (*v1.ControllerRevision, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1.ControllerRevision, error)
	List(ctx context.Context, opts metav1.ListOptions) (*v1.ControllerRevisionList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.ControllerRevision, err error)
	Apply(ctx context.Context, controllerRevision *appsv1.ControllerRevisionApplyConfiguration, opts metav1.ApplyOptions) (result *v1.ControllerRevision, err error)
	ControllerRevisionExpansion
}

// controllerRevisions implements ControllerRevisionInterface
type controllerRevisions struct {
	client rest.Interface
	ns     string
}

// newControllerRevisions returns a ControllerRevisions
func newControllerRevisions(c *AppsV1Client, namespace string) *controllerRevisions {
	return &controllerRevisions{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the controllerRevision, and returns the corresponding controllerRevision object, and an error if there is any.
func (c *controllerRevisions) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.ControllerRevision, err error) {
	result = &v1.ControllerRevision{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("controllerrevisions").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of ControllerRevisions that match those selectors.
func (c *controllerRevisions) List(ctx context.Context, opts metav1.ListOptions) (result *v1.ControllerRevisionList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1.ControllerRevisionList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("controllerrevisions").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested controllerRevisions.
func (c *controllerRevisions) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("controllerrevisions").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a controllerRevision and creates it.  Returns the server's representation of the controllerRevision, and an error, if there is any.
func (c *controllerRevisions) Create(ctx context.Context, controllerRevision *v1.ControllerRevision, opts metav1.CreateOptions) (result *v1.ControllerRevision, err error) {
	result = &v1.ControllerRevision{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("controllerrevisions").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(controllerRevision).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a controllerRevision and updates it. Returns the server's representation of the controllerRevision, and an error, if there is any.
func (c *controllerRevisions) Update(ctx context.Context, controllerRevision *v1.ControllerRevision, opts metav1.UpdateOptions) (result *v1.ControllerRevision, err error) {
	result = &v1.ControllerRevision{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("controllerrevisions").
		Name(controllerRevision.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(controllerRevision).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the controllerRevision and deletes it. Returns an error if one occurs.
func (c *controllerRevisions) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("controllerrevisions").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *controllerRevisions) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("controllerrevisions").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched controllerRevision.
func (c *controllerRevisions) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.ControllerRevision, err error) {
	result = &v1.ControllerRevision{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("controllerrevisions").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// Apply takes the given apply declarative configuration, applies it and returns the applied controllerRevision.
func (c *controllerRevisions) Apply(ctx context.Context, controllerRevision *appsv1.ControllerRevisionApplyConfiguration, opts metav1.ApplyOptions) (result *v1.ControllerRevision, err error) {
	if controllerRevision == nil {
		return nil, fmt.Errorf("controllerRevision provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(controllerRevision)
	if err != nil {
		return nil, err
	}
	name := controllerRevision.Name
	if name == nil {
		return nil, fmt.Errorf("controllerRevision.Name must be provided to Apply")
	}
	result = &v1.ControllerRevision{}
	err = c.client.Patch(types.ApplyPatchType).
		Namespace(c.ns).
		Resource("controllerrevisions").
		Name(*name).
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
