// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v2

import (
	v1 "k8s.io/api/core/v1"
)

// ContainerResourceMetricStatusApplyConfiguration represents an declarative configuration of the ContainerResourceMetricStatus type for use
// with apply.
type ContainerResourceMetricStatusApplyConfiguration struct {
	Name      *v1.ResourceName                     `json:"name,omitempty"`
	Current   *MetricValueStatusApplyConfiguration `json:"current,omitempty"`
	Container *string                              `json:"container,omitempty"`
}

// ContainerResourceMetricStatusApplyConfiguration constructs an declarative configuration of the ContainerResourceMetricStatus type for use with
// apply.
func ContainerResourceMetricStatus() *ContainerResourceMetricStatusApplyConfiguration {
	return &ContainerResourceMetricStatusApplyConfiguration{}
}

// WithName sets the Name field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Name field is set to the value of the last call.
func (b *ContainerResourceMetricStatusApplyConfiguration) WithName(value v1.ResourceName) *ContainerResourceMetricStatusApplyConfiguration {
	b.Name = &value
	return b
}

// WithCurrent sets the Current field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Current field is set to the value of the last call.
func (b *ContainerResourceMetricStatusApplyConfiguration) WithCurrent(value *MetricValueStatusApplyConfiguration) *ContainerResourceMetricStatusApplyConfiguration {
	b.Current = value
	return b
}

// WithContainer sets the Container field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Container field is set to the value of the last call.
func (b *ContainerResourceMetricStatusApplyConfiguration) WithContainer(value string) *ContainerResourceMetricStatusApplyConfiguration {
	b.Container = &value
	return b
}
