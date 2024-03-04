// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

import (
	v1 "k8s.io/api/autoscaling/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// HorizontalPodAutoscalerLister helps list HorizontalPodAutoscalers.
// All objects returned here must be treated as read-only.
type HorizontalPodAutoscalerLister interface {
	// List lists all HorizontalPodAutoscalers in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.HorizontalPodAutoscaler, err error)
	// HorizontalPodAutoscalers returns an object that can list and get HorizontalPodAutoscalers.
	HorizontalPodAutoscalers(namespace string) HorizontalPodAutoscalerNamespaceLister
	HorizontalPodAutoscalerListerExpansion
}

// horizontalPodAutoscalerLister implements the HorizontalPodAutoscalerLister interface.
type horizontalPodAutoscalerLister struct {
	indexer cache.Indexer
}

// NewHorizontalPodAutoscalerLister returns a new HorizontalPodAutoscalerLister.
func NewHorizontalPodAutoscalerLister(indexer cache.Indexer) HorizontalPodAutoscalerLister {
	return &horizontalPodAutoscalerLister{indexer: indexer}
}

// List lists all HorizontalPodAutoscalers in the indexer.
func (s *horizontalPodAutoscalerLister) List(selector labels.Selector) (ret []*v1.HorizontalPodAutoscaler, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.HorizontalPodAutoscaler))
	})
	return ret, err
}

// HorizontalPodAutoscalers returns an object that can list and get HorizontalPodAutoscalers.
func (s *horizontalPodAutoscalerLister) HorizontalPodAutoscalers(namespace string) HorizontalPodAutoscalerNamespaceLister {
	return horizontalPodAutoscalerNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// HorizontalPodAutoscalerNamespaceLister helps list and get HorizontalPodAutoscalers.
// All objects returned here must be treated as read-only.
type HorizontalPodAutoscalerNamespaceLister interface {
	// List lists all HorizontalPodAutoscalers in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.HorizontalPodAutoscaler, err error)
	// Get retrieves the HorizontalPodAutoscaler from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1.HorizontalPodAutoscaler, error)
	HorizontalPodAutoscalerNamespaceListerExpansion
}

// horizontalPodAutoscalerNamespaceLister implements the HorizontalPodAutoscalerNamespaceLister
// interface.
type horizontalPodAutoscalerNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all HorizontalPodAutoscalers in the indexer for a given namespace.
func (s horizontalPodAutoscalerNamespaceLister) List(selector labels.Selector) (ret []*v1.HorizontalPodAutoscaler, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.HorizontalPodAutoscaler))
	})
	return ret, err
}

// Get retrieves the HorizontalPodAutoscaler from the indexer for a given namespace and name.
func (s horizontalPodAutoscalerNamespaceLister) Get(name string) (*v1.HorizontalPodAutoscaler, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1.SchemeResource("horizontalpodautoscaler"), name)
	}
	return obj.(*v1.HorizontalPodAutoscaler), nil
}
