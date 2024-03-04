// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v2

// CrossVersionObjectReferenceApplyConfiguration represents an declarative configuration of the CrossVersionObjectReference type for use
// with apply.
type CrossVersionObjectReferenceApplyConfiguration struct {
	Kind       *string `json:"kind,omitempty"`
	Name       *string `json:"name,omitempty"`
	APIVersion *string `json:"apiVersion,omitempty"`
}

// CrossVersionObjectReferenceApplyConfiguration constructs an declarative configuration of the CrossVersionObjectReference type for use with
// apply.
func CrossVersionObjectReference() *CrossVersionObjectReferenceApplyConfiguration {
	return &CrossVersionObjectReferenceApplyConfiguration{}
}

// WithKind sets the Kind field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Kind field is set to the value of the last call.
func (b *CrossVersionObjectReferenceApplyConfiguration) WithKind(value string) *CrossVersionObjectReferenceApplyConfiguration {
	b.Kind = &value
	return b
}

// WithName sets the Name field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Name field is set to the value of the last call.
func (b *CrossVersionObjectReferenceApplyConfiguration) WithName(value string) *CrossVersionObjectReferenceApplyConfiguration {
	b.Name = &value
	return b
}

// WithAPIVersion sets the APIVersion field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the APIVersion field is set to the value of the last call.
func (b *CrossVersionObjectReferenceApplyConfiguration) WithAPIVersion(value string) *CrossVersionObjectReferenceApplyConfiguration {
	b.APIVersion = &value
	return b
}
