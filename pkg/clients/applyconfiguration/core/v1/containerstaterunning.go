// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ContainerStateRunningApplyConfiguration represents an declarative configuration of the ContainerStateRunning type for use
// with apply.
type ContainerStateRunningApplyConfiguration struct {
	StartedAt *v1.Time `json:"startedAt,omitempty"`
}

// ContainerStateRunningApplyConfiguration constructs an declarative configuration of the ContainerStateRunning type for use with
// apply.
func ContainerStateRunning() *ContainerStateRunningApplyConfiguration {
	return &ContainerStateRunningApplyConfiguration{}
}

// WithStartedAt sets the StartedAt field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the StartedAt field is set to the value of the last call.
func (b *ContainerStateRunningApplyConfiguration) WithStartedAt(value v1.Time) *ContainerStateRunningApplyConfiguration {
	b.StartedAt = &value
	return b
}
