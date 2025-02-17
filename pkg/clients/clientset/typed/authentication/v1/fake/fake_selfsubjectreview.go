// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package fake

import (
	"context"

	v1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	testing "k8s.io/client-go/testing"
)

// FakeSelfSubjectReviews implements SelfSubjectReviewInterface
type FakeSelfSubjectReviews struct {
	Fake *FakeAuthenticationV1
}

var selfsubjectreviewsResource = v1.SchemeGroupVersion.WithResource("selfsubjectreviews")

var selfsubjectreviewsKind = v1.SchemeGroupVersion.WithKind("SelfSubjectReview")

// Create takes the representation of a selfSubjectReview and creates it.  Returns the server's representation of the selfSubjectReview, and an error, if there is any.
func (c *FakeSelfSubjectReviews) Create(ctx context.Context, selfSubjectReview *v1.SelfSubjectReview, opts metav1.CreateOptions) (result *v1.SelfSubjectReview, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(selfsubjectreviewsResource, selfSubjectReview), &v1.SelfSubjectReview{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.SelfSubjectReview), err
}
