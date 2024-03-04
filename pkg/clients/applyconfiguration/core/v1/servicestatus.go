// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

import (
	metav1 "k8s.io/client-go/applyconfigurations/meta/v1"
)

// ServiceStatusApplyConfiguration represents an declarative configuration of the ServiceStatus type for use
// with apply.
type ServiceStatusApplyConfiguration struct {
	LoadBalancer *LoadBalancerStatusApplyConfiguration `json:"loadBalancer,omitempty"`
	Conditions   []metav1.ConditionApplyConfiguration  `json:"conditions,omitempty"`
}

// ServiceStatusApplyConfiguration constructs an declarative configuration of the ServiceStatus type for use with
// apply.
func ServiceStatus() *ServiceStatusApplyConfiguration {
	return &ServiceStatusApplyConfiguration{}
}

// WithLoadBalancer sets the LoadBalancer field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the LoadBalancer field is set to the value of the last call.
func (b *ServiceStatusApplyConfiguration) WithLoadBalancer(value *LoadBalancerStatusApplyConfiguration) *ServiceStatusApplyConfiguration {
	b.LoadBalancer = value
	return b
}

// WithConditions adds the given value to the Conditions field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Conditions field.
func (b *ServiceStatusApplyConfiguration) WithConditions(values ...*metav1.ConditionApplyConfiguration) *ServiceStatusApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithConditions")
		}
		b.Conditions = append(b.Conditions, *values[i])
	}
	return b
}
