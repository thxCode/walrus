// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

// PodSchedulingGateApplyConfiguration represents an declarative configuration of the PodSchedulingGate type for use
// with apply.
type PodSchedulingGateApplyConfiguration struct {
	Name *string `json:"name,omitempty"`
}

// PodSchedulingGateApplyConfiguration constructs an declarative configuration of the PodSchedulingGate type for use with
// apply.
func PodSchedulingGate() *PodSchedulingGateApplyConfiguration {
	return &PodSchedulingGateApplyConfiguration{}
}

// WithName sets the Name field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Name field is set to the value of the last call.
func (b *PodSchedulingGateApplyConfiguration) WithName(value string) *PodSchedulingGateApplyConfiguration {
	b.Name = &value
	return b
}
