// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

// AzureFilePersistentVolumeSourceApplyConfiguration represents an declarative configuration of the AzureFilePersistentVolumeSource type for use
// with apply.
type AzureFilePersistentVolumeSourceApplyConfiguration struct {
	SecretName      *string `json:"secretName,omitempty"`
	ShareName       *string `json:"shareName,omitempty"`
	ReadOnly        *bool   `json:"readOnly,omitempty"`
	SecretNamespace *string `json:"secretNamespace,omitempty"`
}

// AzureFilePersistentVolumeSourceApplyConfiguration constructs an declarative configuration of the AzureFilePersistentVolumeSource type for use with
// apply.
func AzureFilePersistentVolumeSource() *AzureFilePersistentVolumeSourceApplyConfiguration {
	return &AzureFilePersistentVolumeSourceApplyConfiguration{}
}

// WithSecretName sets the SecretName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SecretName field is set to the value of the last call.
func (b *AzureFilePersistentVolumeSourceApplyConfiguration) WithSecretName(value string) *AzureFilePersistentVolumeSourceApplyConfiguration {
	b.SecretName = &value
	return b
}

// WithShareName sets the ShareName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ShareName field is set to the value of the last call.
func (b *AzureFilePersistentVolumeSourceApplyConfiguration) WithShareName(value string) *AzureFilePersistentVolumeSourceApplyConfiguration {
	b.ShareName = &value
	return b
}

// WithReadOnly sets the ReadOnly field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ReadOnly field is set to the value of the last call.
func (b *AzureFilePersistentVolumeSourceApplyConfiguration) WithReadOnly(value bool) *AzureFilePersistentVolumeSourceApplyConfiguration {
	b.ReadOnly = &value
	return b
}

// WithSecretNamespace sets the SecretNamespace field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the SecretNamespace field is set to the value of the last call.
func (b *AzureFilePersistentVolumeSourceApplyConfiguration) WithSecretNamespace(value string) *AzureFilePersistentVolumeSourceApplyConfiguration {
	b.SecretNamespace = &value
	return b
}
