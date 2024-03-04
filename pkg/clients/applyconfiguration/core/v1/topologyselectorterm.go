// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

// TopologySelectorTermApplyConfiguration represents an declarative configuration of the TopologySelectorTerm type for use
// with apply.
type TopologySelectorTermApplyConfiguration struct {
	MatchLabelExpressions []TopologySelectorLabelRequirementApplyConfiguration `json:"matchLabelExpressions,omitempty"`
}

// TopologySelectorTermApplyConfiguration constructs an declarative configuration of the TopologySelectorTerm type for use with
// apply.
func TopologySelectorTerm() *TopologySelectorTermApplyConfiguration {
	return &TopologySelectorTermApplyConfiguration{}
}

// WithMatchLabelExpressions adds the given value to the MatchLabelExpressions field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the MatchLabelExpressions field.
func (b *TopologySelectorTermApplyConfiguration) WithMatchLabelExpressions(values ...*TopologySelectorLabelRequirementApplyConfiguration) *TopologySelectorTermApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithMatchLabelExpressions")
		}
		b.MatchLabelExpressions = append(b.MatchLabelExpressions, *values[i])
	}
	return b
}
