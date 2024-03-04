// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

import (
	"context"
	json "encoding/json"
	"fmt"
	"time"

	storagev1 "github.com/seal-io/walrus/pkg/clients/applyconfiguration/storage/v1"
	scheme "github.com/seal-io/walrus/pkg/clients/clientset/scheme"
	v1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// StorageClassesGetter has a method to return a StorageClassInterface.
// A group's client should implement this interface.
type StorageClassesGetter interface {
	StorageClasses() StorageClassInterface
}

// StorageClassInterface has methods to work with StorageClass resources.
type StorageClassInterface interface {
	Create(ctx context.Context, storageClass *v1.StorageClass, opts metav1.CreateOptions) (*v1.StorageClass, error)
	Update(ctx context.Context, storageClass *v1.StorageClass, opts metav1.UpdateOptions) (*v1.StorageClass, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1.StorageClass, error)
	List(ctx context.Context, opts metav1.ListOptions) (*v1.StorageClassList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.StorageClass, err error)
	Apply(ctx context.Context, storageClass *storagev1.StorageClassApplyConfiguration, opts metav1.ApplyOptions) (result *v1.StorageClass, err error)
	StorageClassExpansion
}

// storageClasses implements StorageClassInterface
type storageClasses struct {
	client rest.Interface
}

// newStorageClasses returns a StorageClasses
func newStorageClasses(c *StorageV1Client) *storageClasses {
	return &storageClasses{
		client: c.RESTClient(),
	}
}

// Get takes name of the storageClass, and returns the corresponding storageClass object, and an error if there is any.
func (c *storageClasses) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.StorageClass, err error) {
	result = &v1.StorageClass{}
	err = c.client.Get().
		Resource("storageclasses").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of StorageClasses that match those selectors.
func (c *storageClasses) List(ctx context.Context, opts metav1.ListOptions) (result *v1.StorageClassList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1.StorageClassList{}
	err = c.client.Get().
		Resource("storageclasses").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested storageClasses.
func (c *storageClasses) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("storageclasses").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a storageClass and creates it.  Returns the server's representation of the storageClass, and an error, if there is any.
func (c *storageClasses) Create(ctx context.Context, storageClass *v1.StorageClass, opts metav1.CreateOptions) (result *v1.StorageClass, err error) {
	result = &v1.StorageClass{}
	err = c.client.Post().
		Resource("storageclasses").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(storageClass).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a storageClass and updates it. Returns the server's representation of the storageClass, and an error, if there is any.
func (c *storageClasses) Update(ctx context.Context, storageClass *v1.StorageClass, opts metav1.UpdateOptions) (result *v1.StorageClass, err error) {
	result = &v1.StorageClass{}
	err = c.client.Put().
		Resource("storageclasses").
		Name(storageClass.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(storageClass).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the storageClass and deletes it. Returns an error if one occurs.
func (c *storageClasses) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.client.Delete().
		Resource("storageclasses").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *storageClasses) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("storageclasses").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched storageClass.
func (c *storageClasses) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.StorageClass, err error) {
	result = &v1.StorageClass{}
	err = c.client.Patch(pt).
		Resource("storageclasses").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// Apply takes the given apply declarative configuration, applies it and returns the applied storageClass.
func (c *storageClasses) Apply(ctx context.Context, storageClass *storagev1.StorageClassApplyConfiguration, opts metav1.ApplyOptions) (result *v1.StorageClass, err error) {
	if storageClass == nil {
		return nil, fmt.Errorf("storageClass provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(storageClass)
	if err != nil {
		return nil, err
	}
	name := storageClass.Name
	if name == nil {
		return nil, fmt.Errorf("storageClass.Name must be provided to Apply")
	}
	result = &v1.StorageClass{}
	err = c.client.Patch(types.ApplyPatchType).
		Resource("storageclasses").
		Name(*name).
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
