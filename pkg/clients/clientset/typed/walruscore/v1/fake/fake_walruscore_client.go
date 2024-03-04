// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package fake

import (
	v1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/walruscore/v1"
	rest "k8s.io/client-go/rest"
	testing "k8s.io/client-go/testing"
)

type FakeWalruscoreV1 struct {
	*testing.Fake
}

func (c *FakeWalruscoreV1) Catalogs(namespace string) v1.CatalogInterface {
	return &FakeCatalogs{c, namespace}
}

func (c *FakeWalruscoreV1) Connectors(namespace string) v1.ConnectorInterface {
	return &FakeConnectors{c, namespace}
}

func (c *FakeWalruscoreV1) Resources(namespace string) v1.ResourceInterface {
	return &FakeResources{c, namespace}
}

func (c *FakeWalruscoreV1) ResourceDefinitions(namespace string) v1.ResourceDefinitionInterface {
	return &FakeResourceDefinitions{c, namespace}
}

func (c *FakeWalruscoreV1) Templates(namespace string) v1.TemplateInterface {
	return &FakeTemplates{c, namespace}
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *FakeWalruscoreV1) RESTClient() rest.Interface {
	var ret *rest.RESTClient
	return ret
}
