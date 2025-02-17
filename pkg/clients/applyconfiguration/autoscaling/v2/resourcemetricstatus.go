// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v2

import (
	v1 "k8s.io/api/core/v1"
)

// ResourceMetricStatusApplyConfiguration represents an declarative configuration of the ResourceMetricStatus type for use
// with apply.
type ResourceMetricStatusApplyConfiguration struct {
	Name    *v1.ResourceName                     `json:"name,omitempty"`
	Current *MetricValueStatusApplyConfiguration `json:"current,omitempty"`
}

// ResourceMetricStatusApplyConfiguration constructs an declarative configuration of the ResourceMetricStatus type for use with
// apply.
func ResourceMetricStatus() *ResourceMetricStatusApplyConfiguration {
	return &ResourceMetricStatusApplyConfiguration{}
}

// WithName sets the Name field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Name field is set to the value of the last call.
func (b *ResourceMetricStatusApplyConfiguration) WithName(value v1.ResourceName) *ResourceMetricStatusApplyConfiguration {
	b.Name = &value
	return b
}

// WithCurrent sets the Current field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Current field is set to the value of the last call.
func (b *ResourceMetricStatusApplyConfiguration) WithCurrent(value *MetricValueStatusApplyConfiguration) *ResourceMetricStatusApplyConfiguration {
	b.Current = value
	return b
}
