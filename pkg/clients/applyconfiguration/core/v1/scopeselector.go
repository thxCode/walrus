// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

// ScopeSelectorApplyConfiguration represents an declarative configuration of the ScopeSelector type for use
// with apply.
type ScopeSelectorApplyConfiguration struct {
	MatchExpressions []ScopedResourceSelectorRequirementApplyConfiguration `json:"matchExpressions,omitempty"`
}

// ScopeSelectorApplyConfiguration constructs an declarative configuration of the ScopeSelector type for use with
// apply.
func ScopeSelector() *ScopeSelectorApplyConfiguration {
	return &ScopeSelectorApplyConfiguration{}
}

// WithMatchExpressions adds the given value to the MatchExpressions field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the MatchExpressions field.
func (b *ScopeSelectorApplyConfiguration) WithMatchExpressions(values ...*ScopedResourceSelectorRequirementApplyConfiguration) *ScopeSelectorApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithMatchExpressions")
		}
		b.MatchExpressions = append(b.MatchExpressions, *values[i])
	}
	return b
}
