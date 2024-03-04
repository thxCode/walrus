// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

import (
	"context"
	time "time"

	clientset "github.com/seal-io/walrus/pkg/clients/clientset"
	internalinterfaces "github.com/seal-io/walrus/pkg/clients/informers/internalinterfaces"
	v1 "github.com/seal-io/walrus/pkg/clients/listers/rbac/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// RoleBindingInformer provides access to a shared informer and lister for
// RoleBindings.
type RoleBindingInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1.RoleBindingLister
}

type roleBindingInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewRoleBindingInformer constructs a new informer for RoleBinding type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewRoleBindingInformer(client clientset.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredRoleBindingInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredRoleBindingInformer constructs a new informer for RoleBinding type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredRoleBindingInformer(client clientset.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.RbacV1().RoleBindings(namespace).List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.RbacV1().RoleBindings(namespace).Watch(context.TODO(), options)
			},
		},
		&rbacv1.RoleBinding{},
		resyncPeriod,
		indexers,
	)
}

func (f *roleBindingInformer) defaultInformer(client clientset.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredRoleBindingInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *roleBindingInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&rbacv1.RoleBinding{}, f.defaultInformer)
}

func (f *roleBindingInformer) Lister() v1.RoleBindingLister {
	return v1.NewRoleBindingLister(f.Informer().GetIndexer())
}
