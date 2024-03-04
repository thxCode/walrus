// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

import (
	"context"
	time "time"

	walrusv1 "github.com/seal-io/walrus/pkg/apis/walrus/v1"
	clientset "github.com/seal-io/walrus/pkg/clients/clientset"
	internalinterfaces "github.com/seal-io/walrus/pkg/clients/informers/internalinterfaces"
	v1 "github.com/seal-io/walrus/pkg/clients/listers/walrus/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// SettingInformer provides access to a shared informer and lister for
// Settings.
type SettingInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1.SettingLister
}

type settingInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewSettingInformer constructs a new informer for Setting type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewSettingInformer(client clientset.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredSettingInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredSettingInformer constructs a new informer for Setting type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredSettingInformer(client clientset.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.WalrusV1().Settings(namespace).List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.WalrusV1().Settings(namespace).Watch(context.TODO(), options)
			},
		},
		&walrusv1.Setting{},
		resyncPeriod,
		indexers,
	)
}

func (f *settingInformer) defaultInformer(client clientset.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredSettingInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *settingInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&walrusv1.Setting{}, f.defaultInformer)
}

func (f *settingInformer) Lister() v1.SettingLister {
	return v1.NewSettingLister(f.Informer().GetIndexer())
}
