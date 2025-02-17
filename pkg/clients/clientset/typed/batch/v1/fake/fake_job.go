// SPDX-FileCopyrightText: 2024 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "walrus", DO NOT EDIT.

package fake

import (
	"context"
	json "encoding/json"
	"fmt"

	batchv1 "github.com/seal-io/walrus/pkg/clients/applyconfiguration/batch/v1"
	v1 "k8s.io/api/batch/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeJobs implements JobInterface
type FakeJobs struct {
	Fake *FakeBatchV1
	ns   string
}

var jobsResource = v1.SchemeGroupVersion.WithResource("jobs")

var jobsKind = v1.SchemeGroupVersion.WithKind("Job")

// Get takes name of the job, and returns the corresponding job object, and an error if there is any.
func (c *FakeJobs) Get(ctx context.Context, name string, options metav1.GetOptions) (result *v1.Job, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(jobsResource, c.ns, name), &v1.Job{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.Job), err
}

// List takes label and field selectors, and returns the list of Jobs that match those selectors.
func (c *FakeJobs) List(ctx context.Context, opts metav1.ListOptions) (result *v1.JobList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(jobsResource, jobsKind, c.ns, opts), &v1.JobList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1.JobList{ListMeta: obj.(*v1.JobList).ListMeta}
	for _, item := range obj.(*v1.JobList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested jobs.
func (c *FakeJobs) Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(jobsResource, c.ns, opts))

}

// Create takes the representation of a job and creates it.  Returns the server's representation of the job, and an error, if there is any.
func (c *FakeJobs) Create(ctx context.Context, job *v1.Job, opts metav1.CreateOptions) (result *v1.Job, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(jobsResource, c.ns, job), &v1.Job{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.Job), err
}

// Update takes the representation of a job and updates it. Returns the server's representation of the job, and an error, if there is any.
func (c *FakeJobs) Update(ctx context.Context, job *v1.Job, opts metav1.UpdateOptions) (result *v1.Job, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(jobsResource, c.ns, job), &v1.Job{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.Job), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeJobs) UpdateStatus(ctx context.Context, job *v1.Job, opts metav1.UpdateOptions) (*v1.Job, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(jobsResource, "status", c.ns, job), &v1.Job{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.Job), err
}

// Delete takes name of the job and deletes it. Returns an error if one occurs.
func (c *FakeJobs) Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(jobsResource, c.ns, name, opts), &v1.Job{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeJobs) DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(jobsResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1.JobList{})
	return err
}

// Patch applies the patch and returns the patched job.
func (c *FakeJobs) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.Job, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(jobsResource, c.ns, name, pt, data, subresources...), &v1.Job{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.Job), err
}

// Apply takes the given apply declarative configuration, applies it and returns the applied job.
func (c *FakeJobs) Apply(ctx context.Context, job *batchv1.JobApplyConfiguration, opts metav1.ApplyOptions) (result *v1.Job, err error) {
	if job == nil {
		return nil, fmt.Errorf("job provided to Apply must not be nil")
	}
	data, err := json.Marshal(job)
	if err != nil {
		return nil, err
	}
	name := job.Name
	if name == nil {
		return nil, fmt.Errorf("job.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(jobsResource, c.ns, *name, types.ApplyPatchType, data), &v1.Job{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.Job), err
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *FakeJobs) ApplyStatus(ctx context.Context, job *batchv1.JobApplyConfiguration, opts metav1.ApplyOptions) (result *v1.Job, err error) {
	if job == nil {
		return nil, fmt.Errorf("job provided to Apply must not be nil")
	}
	data, err := json.Marshal(job)
	if err != nil {
		return nil, err
	}
	name := job.Name
	if name == nil {
		return nil, fmt.Errorf("job.Name must be provided to Apply")
	}
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(jobsResource, c.ns, *name, types.ApplyPatchType, data, "status"), &v1.Job{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1.Job), err
}
