// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package fake

import (
	v1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/admissionregistration/v1"
	rest "k8s.io/client-go/rest"
	testing "k8s.io/client-go/testing"
)

type FakeAdmissionregistrationV1 struct {
	*testing.Fake
}

func (c *FakeAdmissionregistrationV1) MutatingWebhookConfigurations() v1.MutatingWebhookConfigurationInterface {
	return &FakeMutatingWebhookConfigurations{c}
}

func (c *FakeAdmissionregistrationV1) ValidatingWebhookConfigurations() v1.ValidatingWebhookConfigurationInterface {
	return &FakeValidatingWebhookConfigurations{c}
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *FakeAdmissionregistrationV1) RESTClient() rest.Interface {
	var ret *rest.RESTClient
	return ret
}
