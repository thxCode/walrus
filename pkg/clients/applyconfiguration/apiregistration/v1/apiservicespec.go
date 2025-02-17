// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

// APIServiceSpecApplyConfiguration represents an declarative configuration of the APIServiceSpec type for use
// with apply.
type APIServiceSpecApplyConfiguration struct {
	Service               *ServiceReferenceApplyConfiguration `json:"service,omitempty"`
	Group                 *string                             `json:"group,omitempty"`
	Version               *string                             `json:"version,omitempty"`
	InsecureSkipTLSVerify *bool                               `json:"insecureSkipTLSVerify,omitempty"`
	CABundle              []byte                              `json:"caBundle,omitempty"`
	GroupPriorityMinimum  *int32                              `json:"groupPriorityMinimum,omitempty"`
	VersionPriority       *int32                              `json:"versionPriority,omitempty"`
}

// APIServiceSpecApplyConfiguration constructs an declarative configuration of the APIServiceSpec type for use with
// apply.
func APIServiceSpec() *APIServiceSpecApplyConfiguration {
	return &APIServiceSpecApplyConfiguration{}
}

// WithService sets the Service field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Service field is set to the value of the last call.
func (b *APIServiceSpecApplyConfiguration) WithService(value *ServiceReferenceApplyConfiguration) *APIServiceSpecApplyConfiguration {
	b.Service = value
	return b
}

// WithGroup sets the Group field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Group field is set to the value of the last call.
func (b *APIServiceSpecApplyConfiguration) WithGroup(value string) *APIServiceSpecApplyConfiguration {
	b.Group = &value
	return b
}

// WithVersion sets the Version field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Version field is set to the value of the last call.
func (b *APIServiceSpecApplyConfiguration) WithVersion(value string) *APIServiceSpecApplyConfiguration {
	b.Version = &value
	return b
}

// WithInsecureSkipTLSVerify sets the InsecureSkipTLSVerify field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the InsecureSkipTLSVerify field is set to the value of the last call.
func (b *APIServiceSpecApplyConfiguration) WithInsecureSkipTLSVerify(value bool) *APIServiceSpecApplyConfiguration {
	b.InsecureSkipTLSVerify = &value
	return b
}

// WithCABundle adds the given value to the CABundle field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the CABundle field.
func (b *APIServiceSpecApplyConfiguration) WithCABundle(values ...byte) *APIServiceSpecApplyConfiguration {
	for i := range values {
		b.CABundle = append(b.CABundle, values[i])
	}
	return b
}

// WithGroupPriorityMinimum sets the GroupPriorityMinimum field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the GroupPriorityMinimum field is set to the value of the last call.
func (b *APIServiceSpecApplyConfiguration) WithGroupPriorityMinimum(value int32) *APIServiceSpecApplyConfiguration {
	b.GroupPriorityMinimum = &value
	return b
}

// WithVersionPriority sets the VersionPriority field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the VersionPriority field is set to the value of the last call.
func (b *APIServiceSpecApplyConfiguration) WithVersionPriority(value int32) *APIServiceSpecApplyConfiguration {
	b.VersionPriority = &value
	return b
}
