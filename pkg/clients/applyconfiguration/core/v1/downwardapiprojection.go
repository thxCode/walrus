// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

// DownwardAPIProjectionApplyConfiguration represents an declarative configuration of the DownwardAPIProjection type for use
// with apply.
type DownwardAPIProjectionApplyConfiguration struct {
	Items []DownwardAPIVolumeFileApplyConfiguration `json:"items,omitempty"`
}

// DownwardAPIProjectionApplyConfiguration constructs an declarative configuration of the DownwardAPIProjection type for use with
// apply.
func DownwardAPIProjection() *DownwardAPIProjectionApplyConfiguration {
	return &DownwardAPIProjectionApplyConfiguration{}
}

// WithItems adds the given value to the Items field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Items field.
func (b *DownwardAPIProjectionApplyConfiguration) WithItems(values ...*DownwardAPIVolumeFileApplyConfiguration) *DownwardAPIProjectionApplyConfiguration {
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithItems")
		}
		b.Items = append(b.Items, *values[i])
	}
	return b
}
