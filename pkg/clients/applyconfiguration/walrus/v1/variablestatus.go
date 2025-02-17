// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

// VariableStatusApplyConfiguration represents an declarative configuration of the VariableStatus type for use
// with apply.
type VariableStatusApplyConfiguration struct {
	Project     *string `json:"project,omitempty"`
	Environment *string `json:"environment,omitempty"`
	Value       *string `json:"value,omitempty"`
}

// VariableStatusApplyConfiguration constructs an declarative configuration of the VariableStatus type for use with
// apply.
func VariableStatus() *VariableStatusApplyConfiguration {
	return &VariableStatusApplyConfiguration{}
}

// WithProject sets the Project field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Project field is set to the value of the last call.
func (b *VariableStatusApplyConfiguration) WithProject(value string) *VariableStatusApplyConfiguration {
	b.Project = &value
	return b
}

// WithEnvironment sets the Environment field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Environment field is set to the value of the last call.
func (b *VariableStatusApplyConfiguration) WithEnvironment(value string) *VariableStatusApplyConfiguration {
	b.Environment = &value
	return b
}

// WithValue sets the Value field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Value field is set to the value of the last call.
func (b *VariableStatusApplyConfiguration) WithValue(value string) *VariableStatusApplyConfiguration {
	b.Value = &value
	return b
}
