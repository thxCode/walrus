// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

import (
	v1 "k8s.io/api/batch/v1"
)

// PodFailurePolicyOnExitCodesRequirementApplyConfiguration represents an declarative configuration of the PodFailurePolicyOnExitCodesRequirement type for use
// with apply.
type PodFailurePolicyOnExitCodesRequirementApplyConfiguration struct {
	ContainerName *string                                 `json:"containerName,omitempty"`
	Operator      *v1.PodFailurePolicyOnExitCodesOperator `json:"operator,omitempty"`
	Values        []int32                                 `json:"values,omitempty"`
}

// PodFailurePolicyOnExitCodesRequirementApplyConfiguration constructs an declarative configuration of the PodFailurePolicyOnExitCodesRequirement type for use with
// apply.
func PodFailurePolicyOnExitCodesRequirement() *PodFailurePolicyOnExitCodesRequirementApplyConfiguration {
	return &PodFailurePolicyOnExitCodesRequirementApplyConfiguration{}
}

// WithContainerName sets the ContainerName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ContainerName field is set to the value of the last call.
func (b *PodFailurePolicyOnExitCodesRequirementApplyConfiguration) WithContainerName(value string) *PodFailurePolicyOnExitCodesRequirementApplyConfiguration {
	b.ContainerName = &value
	return b
}

// WithOperator sets the Operator field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Operator field is set to the value of the last call.
func (b *PodFailurePolicyOnExitCodesRequirementApplyConfiguration) WithOperator(value v1.PodFailurePolicyOnExitCodesOperator) *PodFailurePolicyOnExitCodesRequirementApplyConfiguration {
	b.Operator = &value
	return b
}

// WithValues adds the given value to the Values field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Values field.
func (b *PodFailurePolicyOnExitCodesRequirementApplyConfiguration) WithValues(values ...int32) *PodFailurePolicyOnExitCodesRequirementApplyConfiguration {
	for i := range values {
		b.Values = append(b.Values, values[i])
	}
	return b
}
