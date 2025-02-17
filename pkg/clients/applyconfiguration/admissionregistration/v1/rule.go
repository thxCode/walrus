// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

import (
	v1 "k8s.io/api/admissionregistration/v1"
)

// RuleApplyConfiguration represents an declarative configuration of the Rule type for use
// with apply.
type RuleApplyConfiguration struct {
	APIGroups   []string      `json:"apiGroups,omitempty"`
	APIVersions []string      `json:"apiVersions,omitempty"`
	Resources   []string      `json:"resources,omitempty"`
	Scope       *v1.ScopeType `json:"scope,omitempty"`
}

// RuleApplyConfiguration constructs an declarative configuration of the Rule type for use with
// apply.
func Rule() *RuleApplyConfiguration {
	return &RuleApplyConfiguration{}
}

// WithAPIGroups adds the given value to the APIGroups field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the APIGroups field.
func (b *RuleApplyConfiguration) WithAPIGroups(values ...string) *RuleApplyConfiguration {
	for i := range values {
		b.APIGroups = append(b.APIGroups, values[i])
	}
	return b
}

// WithAPIVersions adds the given value to the APIVersions field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the APIVersions field.
func (b *RuleApplyConfiguration) WithAPIVersions(values ...string) *RuleApplyConfiguration {
	for i := range values {
		b.APIVersions = append(b.APIVersions, values[i])
	}
	return b
}

// WithResources adds the given value to the Resources field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Resources field.
func (b *RuleApplyConfiguration) WithResources(values ...string) *RuleApplyConfiguration {
	for i := range values {
		b.Resources = append(b.Resources, values[i])
	}
	return b
}

// WithScope sets the Scope field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Scope field is set to the value of the last call.
func (b *RuleApplyConfiguration) WithScope(value v1.ScopeType) *RuleApplyConfiguration {
	b.Scope = &value
	return b
}
