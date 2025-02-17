// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

import (
	"context"
	json "encoding/json"
	"fmt"
	"time"

	corev1 "github.com/seal-io/walrus/pkg/clients/applyconfiguration/core/v1"
	scheme "github.com/seal-io/walrus/pkg/clients/clientset/scheme"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// ConfigMapsGetter has a method to return a ConfigMapInterface.
// A group's client should implement this interface.
type ConfigMapsGetter interface {
	ConfigMaps(namespace string) ConfigMapInterface
}

// ConfigMapInterface has methods to work with ConfigMap resources.
type ConfigMapInterface interface {
	Create(ctx context.Context, configMap *v1.ConfigMap, opts metav1.CreateOptions) (*v1.ConfigMap, error)
	Update(ctx context.Context, configMap *v1.ConfigMap, opts metav1.UpdateOptions) (*v1.ConfigMap, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1.ConfigMap, error)
	List(ctx context.Context, opts metav1.ListOptions) (*v1.ConfigMapList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.ConfigMap, err error)
	Apply(ctx context.Context, configMap *corev1.ConfigMapApplyConfiguration, opts metav1.ApplyOptions) (result *v1.ConfigMap, err error)
	ConfigMapExpansion
}

// configMaps implements ConfigMapInterface
type configMaps struct {
	client rest.Interface
	ns     string
}

// newConfigMaps returns a ConfigMaps
func newConfigMaps(c *CoreV1Client, namespace string) *configMaps {
	return &configMaps{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the configMap, and returns the corresponding configMap object, and an error if there is any.
func (c *configMaps) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.ConfigMap, err error) {
	result = &v1.ConfigMap{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("configmaps").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of ConfigMaps that match those selectors.
func (c *configMaps) List(ctx context.Context, opts metav1.ListOptions) (result *v1.ConfigMapList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1.ConfigMapList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("configmaps").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested configMaps.
func (c *configMaps) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("configmaps").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a configMap and creates it.  Returns the server's representation of the configMap, and an error, if there is any.
func (c *configMaps) Create(ctx context.Context, configMap *v1.ConfigMap, opts metav1.CreateOptions) (result *v1.ConfigMap, err error) {
	result = &v1.ConfigMap{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("configmaps").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(configMap).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a configMap and updates it. Returns the server's representation of the configMap, and an error, if there is any.
func (c *configMaps) Update(ctx context.Context, configMap *v1.ConfigMap, opts metav1.UpdateOptions) (result *v1.ConfigMap, err error) {
	result = &v1.ConfigMap{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("configmaps").
		Name(configMap.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(configMap).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the configMap and deletes it. Returns an error if one occurs.
func (c *configMaps) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("configmaps").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *configMaps) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("configmaps").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched configMap.
func (c *configMaps) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.ConfigMap, err error) {
	result = &v1.ConfigMap{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("configmaps").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// Apply takes the given apply declarative configuration, applies it and returns the applied configMap.
func (c *configMaps) Apply(ctx context.Context, configMap *corev1.ConfigMapApplyConfiguration, opts metav1.ApplyOptions) (result *v1.ConfigMap, err error) {
	if configMap == nil {
		return nil, fmt.Errorf("configMap provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(configMap)
	if err != nil {
		return nil, err
	}
	name := configMap.Name
	if name == nil {
		return nil, fmt.Errorf("configMap.Name must be provided to Apply")
	}
	result = &v1.ConfigMap{}
	err = c.client.Patch(types.ApplyPatchType).
		Namespace(c.ns).
		Resource("configmaps").
		Name(*name).
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
