// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

import (
	v1 "k8s.io/client-go/applyconfigurations/meta/v1"
)

// AggregationRuleApplyConfiguration represents an declarative configuration of the AggregationRule type for use
// with apply.
type AggregationRuleApplyConfiguration struct {
	ClusterRoleSelectors []v1.LabelSelectorApplyConfiguration `json:"clusterRoleSelectors,omitempty"`
}

// AggregationRuleApplyConfiguration constructs an declarative configuration of the AggregationRule type for use with
// apply.
func AggregationRule() *AggregationRuleApplyConfiguration {
	return &AggregationRuleApplyConfiguration{}
}

// WithClusterRoleSelectors adds the given value to the ClusterRoleSelectors field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the ClusterRoleSelectors field.
func (b *AggregationRuleApplyConfiguration) WithClusterRoleSelectors(values ...*v1.LabelSelectorApplyConfiguration) *AggregationRuleApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithClusterRoleSelectors")
		}
		b.ClusterRoleSelectors = append(b.ClusterRoleSelectors, *values[i])
	}
	return b
}
