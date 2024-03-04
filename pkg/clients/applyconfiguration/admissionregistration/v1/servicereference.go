// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

// ServiceReferenceApplyConfiguration represents an declarative configuration of the ServiceReference type for use
// with apply.
type ServiceReferenceApplyConfiguration struct {
	Namespace *string `json:"namespace,omitempty"`
	Name      *string `json:"name,omitempty"`
	Path      *string `json:"path,omitempty"`
	Port      *int32  `json:"port,omitempty"`
}

// ServiceReferenceApplyConfiguration constructs an declarative configuration of the ServiceReference type for use with
// apply.
func ServiceReference() *ServiceReferenceApplyConfiguration {
	return &ServiceReferenceApplyConfiguration{}
}

// WithNamespace sets the Namespace field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Namespace field is set to the value of the last call.
func (b *ServiceReferenceApplyConfiguration) WithNamespace(value string) *ServiceReferenceApplyConfiguration {
	b.Namespace = &value
	return b
}

// WithName sets the Name field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Name field is set to the value of the last call.
func (b *ServiceReferenceApplyConfiguration) WithName(value string) *ServiceReferenceApplyConfiguration {
	b.Name = &value
	return b
}

// WithPath sets the Path field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Path field is set to the value of the last call.
func (b *ServiceReferenceApplyConfiguration) WithPath(value string) *ServiceReferenceApplyConfiguration {
	b.Path = &value
	return b
}

// WithPort sets the Port field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Port field is set to the value of the last call.
func (b *ServiceReferenceApplyConfiguration) WithPort(value int32) *ServiceReferenceApplyConfiguration {
	b.Port = &value
	return b
}
