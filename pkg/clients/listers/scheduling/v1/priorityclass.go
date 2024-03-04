// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

import (
	v1 "k8s.io/api/scheduling/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// PriorityClassLister helps list PriorityClasses.
// All objects returned here must be treated as read-only.
type PriorityClassLister interface {
	// List lists all PriorityClasses in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.PriorityClass, err error)
	// Get retrieves the PriorityClass from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1.PriorityClass, error)
	PriorityClassListerExpansion
}

// priorityClassLister implements the PriorityClassLister interface.
type priorityClassLister struct {
	indexer cache.Indexer
}

// NewPriorityClassLister returns a new PriorityClassLister.
func NewPriorityClassLister(indexer cache.Indexer) PriorityClassLister {
	return &priorityClassLister{indexer: indexer}
}

// List lists all PriorityClasses in the indexer.
func (s *priorityClassLister) List(selector labels.Selector) (ret []*v1.PriorityClass, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.PriorityClass))
	})
	return ret, err
}

// Get retrieves the PriorityClass from the index for a given name.
func (s *priorityClassLister) Get(name string) (*v1.PriorityClass, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1.SchemeResource("priorityclass"), name)
	}
	return obj.(*v1.PriorityClass), nil
}
