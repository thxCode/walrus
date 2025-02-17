// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

import (
	v1 "github.com/seal-io/walrus/pkg/apis/walrus/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// TemplateCompletionExampleLister helps list TemplateCompletionExamples.
// All objects returned here must be treated as read-only.
type TemplateCompletionExampleLister interface {
	// List lists all TemplateCompletionExamples in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.TemplateCompletionExample, err error)
	// TemplateCompletionExamples returns an object that can list and get TemplateCompletionExamples.
	TemplateCompletionExamples(namespace string) TemplateCompletionExampleNamespaceLister
	TemplateCompletionExampleListerExpansion
}

// templateCompletionExampleLister implements the TemplateCompletionExampleLister interface.
type templateCompletionExampleLister struct {
	indexer cache.Indexer
}

// NewTemplateCompletionExampleLister returns a new TemplateCompletionExampleLister.
func NewTemplateCompletionExampleLister(indexer cache.Indexer) TemplateCompletionExampleLister {
	return &templateCompletionExampleLister{indexer: indexer}
}

// List lists all TemplateCompletionExamples in the indexer.
func (s *templateCompletionExampleLister) List(selector labels.Selector) (ret []*v1.TemplateCompletionExample, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.TemplateCompletionExample))
	})
	return ret, err
}

// TemplateCompletionExamples returns an object that can list and get TemplateCompletionExamples.
func (s *templateCompletionExampleLister) TemplateCompletionExamples(namespace string) TemplateCompletionExampleNamespaceLister {
	return templateCompletionExampleNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// TemplateCompletionExampleNamespaceLister helps list and get TemplateCompletionExamples.
// All objects returned here must be treated as read-only.
type TemplateCompletionExampleNamespaceLister interface {
	// List lists all TemplateCompletionExamples in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.TemplateCompletionExample, err error)
	// Get retrieves the TemplateCompletionExample from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1.TemplateCompletionExample, error)
	TemplateCompletionExampleNamespaceListerExpansion
}

// templateCompletionExampleNamespaceLister implements the TemplateCompletionExampleNamespaceLister
// interface.
type templateCompletionExampleNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all TemplateCompletionExamples in the indexer for a given namespace.
func (s templateCompletionExampleNamespaceLister) List(selector labels.Selector) (ret []*v1.TemplateCompletionExample, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.TemplateCompletionExample))
	})
	return ret, err
}

// Get retrieves the TemplateCompletionExample from the indexer for a given namespace and name.
func (s templateCompletionExampleNamespaceLister) Get(name string) (*v1.TemplateCompletionExample, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1.SchemeResource("templatecompletionexample"), name)
	}
	return obj.(*v1.TemplateCompletionExample), nil
}
