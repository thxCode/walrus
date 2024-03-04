// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

// ContainerStateApplyConfiguration represents an declarative configuration of the ContainerState type for use
// with apply.
type ContainerStateApplyConfiguration struct {
	Waiting    *ContainerStateWaitingApplyConfiguration    `json:"waiting,omitempty"`
	Running    *ContainerStateRunningApplyConfiguration    `json:"running,omitempty"`
	Terminated *ContainerStateTerminatedApplyConfiguration `json:"terminated,omitempty"`
}

// ContainerStateApplyConfiguration constructs an declarative configuration of the ContainerState type for use with
// apply.
func ContainerState() *ContainerStateApplyConfiguration {
	return &ContainerStateApplyConfiguration{}
}

// WithWaiting sets the Waiting field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Waiting field is set to the value of the last call.
func (b *ContainerStateApplyConfiguration) WithWaiting(value *ContainerStateWaitingApplyConfiguration) *ContainerStateApplyConfiguration {
	b.Waiting = value
	return b
}

// WithRunning sets the Running field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Running field is set to the value of the last call.
func (b *ContainerStateApplyConfiguration) WithRunning(value *ContainerStateRunningApplyConfiguration) *ContainerStateApplyConfiguration {
	b.Running = value
	return b
}

// WithTerminated sets the Terminated field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Terminated field is set to the value of the last call.
func (b *ContainerStateApplyConfiguration) WithTerminated(value *ContainerStateTerminatedApplyConfiguration) *ContainerStateApplyConfiguration {
	b.Terminated = value
	return b
}
