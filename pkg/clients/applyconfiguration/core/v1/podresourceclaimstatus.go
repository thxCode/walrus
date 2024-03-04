// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

// PodResourceClaimStatusApplyConfiguration represents an declarative configuration of the PodResourceClaimStatus type for use
// with apply.
type PodResourceClaimStatusApplyConfiguration struct {
	Name              *string `json:"name,omitempty"`
	ResourceClaimName *string `json:"resourceClaimName,omitempty"`
}

// PodResourceClaimStatusApplyConfiguration constructs an declarative configuration of the PodResourceClaimStatus type for use with
// apply.
func PodResourceClaimStatus() *PodResourceClaimStatusApplyConfiguration {
	return &PodResourceClaimStatusApplyConfiguration{}
}

// WithName sets the Name field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Name field is set to the value of the last call.
func (b *PodResourceClaimStatusApplyConfiguration) WithName(value string) *PodResourceClaimStatusApplyConfiguration {
	b.Name = &value
	return b
}

// WithResourceClaimName sets the ResourceClaimName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ResourceClaimName field is set to the value of the last call.
func (b *PodResourceClaimStatusApplyConfiguration) WithResourceClaimName(value string) *PodResourceClaimStatusApplyConfiguration {
	b.ResourceClaimName = &value
	return b
}
