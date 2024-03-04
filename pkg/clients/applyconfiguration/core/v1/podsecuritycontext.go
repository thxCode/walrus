// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

import (
	corev1 "k8s.io/api/core/v1"
)

// PodSecurityContextApplyConfiguration represents an declarative configuration of the PodSecurityContext type for use
// with apply.
type PodSecurityContextApplyConfiguration struct {
	SELinuxOptions      *SELinuxOptionsApplyConfiguration                `json:"seLinuxOptions,omitempty"`
	WindowsOptions      *WindowsSecurityContextOptionsApplyConfiguration `json:"windowsOptions,omitempty"`
	RunAsUser           *int64                                           `json:"runAsUser,omitempty"`
	RunAsGroup          *int64                                           `json:"runAsGroup,omitempty"`
	RunAsNonRoot        *bool                                            `json:"runAsNonRoot,omitempty"`
	SupplementalGroups  []int64                                          `json:"supplementalGroups,omitempty"`
	FSGroup             *int64                                           `json:"fsGroup,omitempty"`
	Sysctls             []SysctlApplyConfiguration                       `json:"sysctls,omitempty"`
	FSGroupChangePolicy *corev1.PodFSGroupChangePolicy                   `json:"fsGroupChangePolicy,omitempty"`
	SeccompProfile      *SeccompProfileApplyConfiguration                `json:"seccompProfile,omitempty"`
}

// PodSecurityContextApplyConfiguration constructs an declarative configuration of the PodSecurityContext type for use with
// apply.
func PodSecurityContext() *PodSecurityContextApplyConfiguration {
	return &PodSecurityContextApplyConfiguration{}
}

// WithSELinuxOptions sets the SELinuxOptions field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SELinuxOptions field is set to the value of the last call.
func (b *PodSecurityContextApplyConfiguration) WithSELinuxOptions(value *SELinuxOptionsApplyConfiguration) *PodSecurityContextApplyConfiguration {
	b.SELinuxOptions = value
	return b
}

// WithWindowsOptions sets the WindowsOptions field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the WindowsOptions field is set to the value of the last call.
func (b *PodSecurityContextApplyConfiguration) WithWindowsOptions(value *WindowsSecurityContextOptionsApplyConfiguration) *PodSecurityContextApplyConfiguration {
	b.WindowsOptions = value
	return b
}

// WithRunAsUser sets the RunAsUser field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the RunAsUser field is set to the value of the last call.
func (b *PodSecurityContextApplyConfiguration) WithRunAsUser(value int64) *PodSecurityContextApplyConfiguration {
	b.RunAsUser = &value
	return b
}

// WithRunAsGroup sets the RunAsGroup field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the RunAsGroup field is set to the value of the last call.
func (b *PodSecurityContextApplyConfiguration) WithRunAsGroup(value int64) *PodSecurityContextApplyConfiguration {
	b.RunAsGroup = &value
	return b
}

// WithRunAsNonRoot sets the RunAsNonRoot field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the RunAsNonRoot field is set to the value of the last call.
func (b *PodSecurityContextApplyConfiguration) WithRunAsNonRoot(value bool) *PodSecurityContextApplyConfiguration {
	b.RunAsNonRoot = &value
	return b
}

// WithSupplementalGroups adds the given value to the SupplementalGroups field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the SupplementalGroups field.
func (b *PodSecurityContextApplyConfiguration) WithSupplementalGroups(values ...int64) *PodSecurityContextApplyConfiguration {
	for i := range values {
		b.SupplementalGroups = append(b.SupplementalGroups, values[i])
	}
	return b
}

// WithFSGroup sets the FSGroup field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the FSGroup field is set to the value of the last call.
func (b *PodSecurityContextApplyConfiguration) WithFSGroup(value int64) *PodSecurityContextApplyConfiguration {
	b.FSGroup = &value
	return b
}

// WithSysctls adds the given value to the Sysctls field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Sysctls field.
func (b *PodSecurityContextApplyConfiguration) WithSysctls(values ...*SysctlApplyConfiguration) *PodSecurityContextApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithSysctls")
		}
		b.Sysctls = append(b.Sysctls, *values[i])
	}
	return b
}

// WithFSGroupChangePolicy sets the FSGroupChangePolicy field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the FSGroupChangePolicy field is set to the value of the last call.
func (b *PodSecurityContextApplyConfiguration) WithFSGroupChangePolicy(value corev1.PodFSGroupChangePolicy) *PodSecurityContextApplyConfiguration {
	b.FSGroupChangePolicy = &value
	return b
}

// WithSeccompProfile sets the SeccompProfile field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SeccompProfile field is set to the value of the last call.
func (b *PodSecurityContextApplyConfiguration) WithSeccompProfile(value *SeccompProfileApplyConfiguration) *PodSecurityContextApplyConfiguration {
	b.SeccompProfile = value
	return b
}
