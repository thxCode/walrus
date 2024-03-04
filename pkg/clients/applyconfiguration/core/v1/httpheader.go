// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

// HTTPHeaderApplyConfiguration represents an declarative configuration of the HTTPHeader type for use
// with apply.
type HTTPHeaderApplyConfiguration struct {
	Name  *string `json:"name,omitempty"`
	Value *string `json:"value,omitempty"`
}

// HTTPHeaderApplyConfiguration constructs an declarative configuration of the HTTPHeader type for use with
// apply.
func HTTPHeader() *HTTPHeaderApplyConfiguration {
	return &HTTPHeaderApplyConfiguration{}
}

// WithName sets the Name field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Name field is set to the value of the last call.
func (b *HTTPHeaderApplyConfiguration) WithName(value string) *HTTPHeaderApplyConfiguration {
	b.Name = &value
	return b
}

// WithValue sets the Value field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Value field is set to the value of the last call.
func (b *HTTPHeaderApplyConfiguration) WithValue(value string) *HTTPHeaderApplyConfiguration {
	b.Value = &value
	return b
}
