// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

import (
	"context"
	time "time"

	clientset "github.com/seal-io/walrus/pkg/clients/clientset"
	internalinterfaces "github.com/seal-io/walrus/pkg/clients/informers/internalinterfaces"
	v1 "github.com/seal-io/walrus/pkg/clients/listers/storage/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// VolumeAttachmentInformer provides access to a shared informer and lister for
// VolumeAttachments.
type VolumeAttachmentInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1.VolumeAttachmentLister
}

type volumeAttachmentInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// NewVolumeAttachmentInformer constructs a new informer for VolumeAttachment type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewVolumeAttachmentInformer(client clientset.Interface, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredVolumeAttachmentInformer(client, resyncPeriod, indexers, nil)
}

// NewFilteredVolumeAttachmentInformer constructs a new informer for VolumeAttachment type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredVolumeAttachmentInformer(client clientset.Interface, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.StorageV1().VolumeAttachments().List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.StorageV1().VolumeAttachments().Watch(context.TODO(), options)
			},
		},
		&storagev1.VolumeAttachment{},
		resyncPeriod,
		indexers,
	)
}

func (f *volumeAttachmentInformer) defaultInformer(client clientset.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredVolumeAttachmentInformer(client, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *volumeAttachmentInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&storagev1.VolumeAttachment{}, f.defaultInformer)
}

func (f *volumeAttachmentInformer) Lister() v1.VolumeAttachmentLister {
	return v1.NewVolumeAttachmentLister(f.Informer().GetIndexer())
}
