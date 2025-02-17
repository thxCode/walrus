// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

// SettingSpecApplyConfiguration represents an declarative configuration of the SettingSpec type for use
// with apply.
type SettingSpecApplyConfiguration struct {
	Value *string `json:"value,omitempty"`
}

// SettingSpecApplyConfiguration constructs an declarative configuration of the SettingSpec type for use with
// apply.
func SettingSpec() *SettingSpecApplyConfiguration {
	return &SettingSpecApplyConfiguration{}
}

// WithValue sets the Value field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Value field is set to the value of the last call.
func (b *SettingSpecApplyConfiguration) WithValue(value string) *SettingSpecApplyConfiguration {
	b.Value = &value
	return b
}
