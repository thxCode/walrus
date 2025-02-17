// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package fake

import (
	v1 "github.com/seal-io/walrus/pkg/clients/clientset/typed/batch/v1"
	rest "k8s.io/client-go/rest"
	testing "k8s.io/client-go/testing"
)

type FakeBatchV1 struct {
	*testing.Fake
}

func (c *FakeBatchV1) CronJobs(namespace string) v1.CronJobInterface {
	return &FakeCronJobs{c, namespace}
}

func (c *FakeBatchV1) Jobs(namespace string) v1.JobInterface {
	return &FakeJobs{c, namespace}
}

// RESTClient returns a RESTClient that is used to communicate
// with API server by this client implementation.
func (c *FakeBatchV1) RESTClient() rest.Interface {
	var ret *rest.RESTClient
	return ret
}
