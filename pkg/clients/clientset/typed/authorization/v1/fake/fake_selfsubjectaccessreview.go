// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package fake

import (
	"context"

	v1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	testing "k8s.io/client-go/testing"
)

// FakeSelfSubjectAccessReviews implements SelfSubjectAccessReviewInterface
type FakeSelfSubjectAccessReviews struct {
	Fake *FakeAuthorizationV1
}

var selfsubjectaccessreviewsResource = v1.SchemeGroupVersion.WithResource("selfsubjectaccessreviews")

var selfsubjectaccessreviewsKind = v1.SchemeGroupVersion.WithKind("SelfSubjectAccessReview")

// Create takes the representation of a selfSubjectAccessReview and creates it.  Returns the server's representation of the selfSubjectAccessReview, and an error, if there is any.
func (c *FakeSelfSubjectAccessReviews) Create(ctx context.Context, selfSubjectAccessReview *v1.SelfSubjectAccessReview, opts metav1.CreateOptions) (result *v1.SelfSubjectAccessReview, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(selfsubjectaccessreviewsResource, selfSubjectAccessReview), &v1.SelfSubjectAccessReview{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1.SelfSubjectAccessReview), err
}
