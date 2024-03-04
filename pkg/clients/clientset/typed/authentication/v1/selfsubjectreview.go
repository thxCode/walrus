// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package v1

import (
	"context"

	scheme "github.com/seal-io/walrus/pkg/clients/clientset/scheme"
	v1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	rest "k8s.io/client-go/rest"
)

// SelfSubjectReviewsGetter has a method to return a SelfSubjectReviewInterface.
// A group's client should implement this interface.
type SelfSubjectReviewsGetter interface {
	SelfSubjectReviews() SelfSubjectReviewInterface
}

// SelfSubjectReviewInterface has methods to work with SelfSubjectReview resources.
type SelfSubjectReviewInterface interface {
	Create(ctx context.Context, selfSubjectReview *v1.SelfSubjectReview, opts metav1.CreateOptions) (*v1.SelfSubjectReview, error)
	SelfSubjectReviewExpansion
}

// selfSubjectReviews implements SelfSubjectReviewInterface
type selfSubjectReviews struct {
	client rest.Interface
}

// newSelfSubjectReviews returns a SelfSubjectReviews
func newSelfSubjectReviews(c *AuthenticationV1Client) *selfSubjectReviews {
	return &selfSubjectReviews{
		client: c.RESTClient(),
	}
}

// Create takes the representation of a selfSubjectReview and creates it.  Returns the server's representation of the selfSubjectReview, and an error, if there is any.
func (c *selfSubjectReviews) Create(ctx context.Context, selfSubjectReview *v1.SelfSubjectReview, opts metav1.CreateOptions) (result *v1.SelfSubjectReview, err error) {
	result = &v1.SelfSubjectReview{}
	err = c.client.Post().
		Resource("selfsubjectreviews").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(selfSubjectReview).
		Do(ctx).
		Into(result)
	return
}
