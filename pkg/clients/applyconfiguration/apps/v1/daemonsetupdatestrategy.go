// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

import (
	v1 "k8s.io/api/apps/v1"
)

// DaemonSetUpdateStrategyApplyConfiguration represents an declarative configuration of the DaemonSetUpdateStrategy type for use
// with apply.
type DaemonSetUpdateStrategyApplyConfiguration struct {
	Type          *v1.DaemonSetUpdateStrategyType           `json:"type,omitempty"`
	RollingUpdate *RollingUpdateDaemonSetApplyConfiguration `json:"rollingUpdate,omitempty"`
}

// DaemonSetUpdateStrategyApplyConfiguration constructs an declarative configuration of the DaemonSetUpdateStrategy type for use with
// apply.
func DaemonSetUpdateStrategy() *DaemonSetUpdateStrategyApplyConfiguration {
	return &DaemonSetUpdateStrategyApplyConfiguration{}
}

// WithType sets the Type field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Type field is set to the value of the last call.
func (b *DaemonSetUpdateStrategyApplyConfiguration) WithType(value v1.DaemonSetUpdateStrategyType) *DaemonSetUpdateStrategyApplyConfiguration {
	b.Type = &value
	return b
}

// WithRollingUpdate sets the RollingUpdate field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the RollingUpdate field is set to the value of the last call.
func (b *DaemonSetUpdateStrategyApplyConfiguration) WithRollingUpdate(value *RollingUpdateDaemonSetApplyConfiguration) *DaemonSetUpdateStrategyApplyConfiguration {
	b.RollingUpdate = value
	return b
}
