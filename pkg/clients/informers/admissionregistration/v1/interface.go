// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

import (
	internalinterfaces "github.com/seal-io/walrus/pkg/clients/informers/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// MutatingWebhookConfigurations returns a MutatingWebhookConfigurationInformer.
	MutatingWebhookConfigurations() MutatingWebhookConfigurationInformer
	// ValidatingWebhookConfigurations returns a ValidatingWebhookConfigurationInformer.
	ValidatingWebhookConfigurations() ValidatingWebhookConfigurationInformer
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

// MutatingWebhookConfigurations returns a MutatingWebhookConfigurationInformer.
func (v *version) MutatingWebhookConfigurations() MutatingWebhookConfigurationInformer {
	return &mutatingWebhookConfigurationInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}

// ValidatingWebhookConfigurations returns a ValidatingWebhookConfigurationInformer.
func (v *version) ValidatingWebhookConfigurations() ValidatingWebhookConfigurationInformer {
	return &validatingWebhookConfigurationInformer{factory: v.factory, tweakListOptions: v.tweakListOptions}
}
