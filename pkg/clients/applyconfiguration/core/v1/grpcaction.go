// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

// GRPCActionApplyConfiguration represents an declarative configuration of the GRPCAction type for use
// with apply.
type GRPCActionApplyConfiguration struct {
	Port    *int32  `json:"port,omitempty"`
	Service *string `json:"service,omitempty"`
}

// GRPCActionApplyConfiguration constructs an declarative configuration of the GRPCAction type for use with
// apply.
func GRPCAction() *GRPCActionApplyConfiguration {
	return &GRPCActionApplyConfiguration{}
}

// WithPort sets the Port field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Port field is set to the value of the last call.
func (b *GRPCActionApplyConfiguration) WithPort(value int32) *GRPCActionApplyConfiguration {
	b.Port = &value
	return b
}

// WithService sets the Service field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Service field is set to the value of the last call.
func (b *GRPCActionApplyConfiguration) WithService(value string) *GRPCActionApplyConfiguration {
	b.Service = &value
	return b
}
