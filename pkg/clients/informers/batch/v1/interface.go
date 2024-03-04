// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

import (
	internalinterfaces "github.com/seal-io/walrus/pkg/clients/informers/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// CronJobs returns a CronJobInformer.
	CronJobs() CronJobInformer
	// Jobs returns a JobInformer.
	Jobs() JobInformer
}

type version struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &version{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// CronJobs returns a CronJobInformer.
func (v *version) CronJobs() CronJobInformer {
	return &cronJobInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// Jobs returns a JobInformer.
func (v *version) Jobs() JobInformer {
	return &jobInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}
