// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

import (
	v1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// ReplicaSetLister helps list ReplicaSets.
// All objects returned here must be treated as read-only.
type ReplicaSetLister interface {
	// List lists all ReplicaSets in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.ReplicaSet, err error)
	// ReplicaSets returns an object that can list and get ReplicaSets.
	ReplicaSets(namespace string) ReplicaSetNamespaceLister
	ReplicaSetListerExpansion
}

// replicaSetLister implements the ReplicaSetLister interface.
type replicaSetLister struct {
	indexer cache.Indexer
}

// NewReplicaSetLister returns a new ReplicaSetLister.
func NewReplicaSetLister(indexer cache.Indexer) ReplicaSetLister {
	return &replicaSetLister{indexer: indexer}
}

// List lists all ReplicaSets in the indexer.
func (s *replicaSetLister) List(selector labels.Selector) (ret []*v1.ReplicaSet, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.ReplicaSet))
	})
	return ret, err
}

// ReplicaSets returns an object that can list and get ReplicaSets.
func (s *replicaSetLister) ReplicaSets(namespace string) ReplicaSetNamespaceLister {
	return replicaSetNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// ReplicaSetNamespaceLister helps list and get ReplicaSets.
// All objects returned here must be treated as read-only.
type ReplicaSetNamespaceLister interface {
	// List lists all ReplicaSets in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.ReplicaSet, err error)
	// Get retrieves the ReplicaSet from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1.ReplicaSet, error)
	ReplicaSetNamespaceListerExpansion
}

// replicaSetNamespaceLister implements the ReplicaSetNamespaceLister
// interface.
type replicaSetNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all ReplicaSets in the indexer for a given namespace.
func (s replicaSetNamespaceLister) List(selector labels.Selector) (ret []*v1.ReplicaSet, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.ReplicaSet))
	})
	return ret, err
}

// Get retrieves the ReplicaSet from the indexer for a given namespace and name.
func (s replicaSetNamespaceLister) Get(name string) (*v1.ReplicaSet, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1.SchemeResource("replicaset"), name)
	}
	return obj.(*v1.ReplicaSet), nil
}
