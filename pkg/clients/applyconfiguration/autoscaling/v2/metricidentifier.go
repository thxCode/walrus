// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v2

import (
	v1 "k8s.io/client-go/applyconfigurations/meta/v1"
)

// MetricIdentifierApplyConfiguration represents an declarative configuration of the MetricIdentifier type for use
// with apply.
type MetricIdentifierApplyConfiguration struct {
	Name     *string                             `json:"name,omitempty"`
	Selector *v1.LabelSelectorApplyConfiguration `json:"selector,omitempty"`
}

// MetricIdentifierApplyConfiguration constructs an declarative configuration of the MetricIdentifier type for use with
// apply.
func MetricIdentifier() *MetricIdentifierApplyConfiguration {
	return &MetricIdentifierApplyConfiguration{}
}

// WithName sets the Name field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Name field is set to the value of the last call.
func (b *MetricIdentifierApplyConfiguration) WithName(value string) *MetricIdentifierApplyConfiguration {
	b.Name = &value
	return b
}

// WithSelector sets the Selector field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Selector field is set to the value of the last call.
func (b *MetricIdentifierApplyConfiguration) WithSelector(value *v1.LabelSelectorApplyConfiguration) *MetricIdentifierApplyConfiguration {
	b.Selector = value
	return b
}
