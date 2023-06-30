// SPDX-FileCopyrightText: 2023 Seal, Inc
// SPDX-License-Identifier: Apache-2.0

// Code generated by "ent". DO NOT EDIT.

package model

import (
	"time"

	"github.com/seal-io/seal/pkg/dao/types"
	"github.com/seal-io/seal/pkg/dao/types/crypto"
	"github.com/seal-io/seal/pkg/dao/types/oid"
	"github.com/seal-io/seal/pkg/dao/types/property"
)

// ServiceRevisionQueryInput is the input for the ServiceRevision query.
type ServiceRevisionQueryInput struct {
	// ID holds the value of the "id" field.
	ID oid.ID `uri:"id,omitempty" json:"id,omitempty"`
}

// Model converts the ServiceRevisionQueryInput to ServiceRevision.
func (in ServiceRevisionQueryInput) Model() *ServiceRevision {
	return &ServiceRevision{
		ID: in.ID,
	}
}

// ServiceRevisionCreateInput is the input for the ServiceRevision creation.
type ServiceRevisionCreateInput struct {
	// ID of the template.
	TemplateID string `json:"templateID"`
	// Version of the template.
	TemplateVersion string `json:"templateVersion"`
	// Attributes to configure the template.
	Attributes property.Values `json:"attributes,omitempty"`
	// Variables of the revision.
	Variables crypto.Map[string, string] `json:"variables,omitempty"`
	// Input plan of the revision.
	InputPlan string `json:"inputPlan,omitempty"`
	// Output of the revision.
	Output string `json:"output,omitempty"`
	// Type of deployer.
	DeployerType string `json:"deployerType,omitempty"`
	// Duration in seconds of the revision deploying.
	Duration int `json:"duration,omitempty"`
	// Previous provider requirement of the revision.
	PreviousRequiredProviders []types.ProviderRequirement `json:"previousRequiredProviders,omitempty"`
	// Tags of the revision.
	Tags []string `json:"tags,omitempty"`
}

// Model converts the ServiceRevisionCreateInput to ServiceRevision.
func (in ServiceRevisionCreateInput) Model() *ServiceRevision {
	var entity = &ServiceRevision{
		TemplateID:                in.TemplateID,
		TemplateVersion:           in.TemplateVersion,
		Attributes:                in.Attributes,
		Variables:                 in.Variables,
		InputPlan:                 in.InputPlan,
		Output:                    in.Output,
		DeployerType:              in.DeployerType,
		Duration:                  in.Duration,
		PreviousRequiredProviders: in.PreviousRequiredProviders,
		Tags:                      in.Tags,
	}
	return entity
}

// ServiceRevisionUpdateInput is the input for the ServiceRevision modification.
type ServiceRevisionUpdateInput struct {
	// ID holds the value of the "id" field.
	ID oid.ID `uri:"id" json:"-"`
	// Version of the template.
	TemplateVersion string `json:"templateVersion,omitempty"`
	// Attributes to configure the template.
	Attributes property.Values `json:"attributes,omitempty"`
	// Variables of the revision.
	Variables crypto.Map[string, string] `json:"variables,omitempty"`
	// Input plan of the revision.
	InputPlan string `json:"inputPlan,omitempty"`
	// Output of the revision.
	Output string `json:"output,omitempty"`
	// Type of deployer.
	DeployerType string `json:"deployerType,omitempty"`
	// Duration in seconds of the revision deploying.
	Duration int `json:"duration,omitempty"`
	// Previous provider requirement of the revision.
	PreviousRequiredProviders []types.ProviderRequirement `json:"previousRequiredProviders,omitempty"`
	// Tags of the revision.
	Tags []string `json:"tags,omitempty"`
}

// Model converts the ServiceRevisionUpdateInput to ServiceRevision.
func (in ServiceRevisionUpdateInput) Model() *ServiceRevision {
	var entity = &ServiceRevision{
		ID:                        in.ID,
		TemplateVersion:           in.TemplateVersion,
		Attributes:                in.Attributes,
		Variables:                 in.Variables,
		InputPlan:                 in.InputPlan,
		Output:                    in.Output,
		DeployerType:              in.DeployerType,
		Duration:                  in.Duration,
		PreviousRequiredProviders: in.PreviousRequiredProviders,
		Tags:                      in.Tags,
	}
	return entity
}

// ServiceRevisionOutput is the output for the ServiceRevision.
type ServiceRevisionOutput struct {
	// ID holds the value of the "id" field.
	ID oid.ID `json:"id,omitempty"`
	// CreateTime holds the value of the "createTime" field.
	CreateTime *time.Time `json:"createTime,omitempty"`
	// Status holds the value of the "status" field.
	Status string `json:"status,omitempty"`
	// StatusMessage holds the value of the "statusMessage" field.
	StatusMessage string `json:"statusMessage,omitempty"`
	// ID of the template.
	TemplateID string `json:"templateID,omitempty"`
	// Version of the template.
	TemplateVersion string `json:"templateVersion,omitempty"`
	// Attributes to configure the template.
	Attributes property.Values `json:"attributes,omitempty"`
	// Variables of the revision.
	Variables crypto.Map[string, string] `json:"variables,omitempty"`
	// Type of deployer.
	DeployerType string `json:"deployerType,omitempty"`
	// Duration in seconds of the revision deploying.
	Duration int `json:"duration,omitempty"`
	// Previous provider requirement of the revision.
	PreviousRequiredProviders []types.ProviderRequirement `json:"previousRequiredProviders,omitempty"`
	// Tags of the revision.
	Tags []string `json:"tags,omitempty"`
	// Project to which the revision belongs.
	Project *ProjectOutput `json:"project,omitempty"`
	// Environment to which the revision deploys.
	Environment *EnvironmentOutput `json:"environment,omitempty"`
	// Service to which the revision belongs.
	Service *ServiceOutput `json:"service,omitempty"`
}

// ExposeServiceRevision converts the ServiceRevision to ServiceRevisionOutput.
func ExposeServiceRevision(in *ServiceRevision) *ServiceRevisionOutput {
	if in == nil {
		return nil
	}
	var entity = &ServiceRevisionOutput{
		ID:                        in.ID,
		CreateTime:                in.CreateTime,
		Status:                    in.Status,
		StatusMessage:             in.StatusMessage,
		TemplateID:                in.TemplateID,
		TemplateVersion:           in.TemplateVersion,
		Attributes:                in.Attributes,
		Variables:                 in.Variables,
		DeployerType:              in.DeployerType,
		Duration:                  in.Duration,
		PreviousRequiredProviders: in.PreviousRequiredProviders,
		Tags:                      in.Tags,
		Project:                   ExposeProject(in.Edges.Project),
		Environment:               ExposeEnvironment(in.Edges.Environment),
		Service:                   ExposeService(in.Edges.Service),
	}
	if in.ProjectID != "" {
		if entity.Project == nil {
			entity.Project = &ProjectOutput{}
		}
		entity.Project.ID = in.ProjectID
	}
	if in.EnvironmentID != "" {
		if entity.Environment == nil {
			entity.Environment = &EnvironmentOutput{}
		}
		entity.Environment.ID = in.EnvironmentID
	}
	if in.ServiceID != "" {
		if entity.Service == nil {
			entity.Service = &ServiceOutput{}
		}
		entity.Service.ID = in.ServiceID
	}
	return entity
}

// ExposeServiceRevisions converts the ServiceRevision slice to ServiceRevisionOutput pointer slice.
func ExposeServiceRevisions(in []*ServiceRevision) []*ServiceRevisionOutput {
	var out = make([]*ServiceRevisionOutput, 0, len(in))
	for i := 0; i < len(in); i++ {
		var o = ExposeServiceRevision(in[i])
		if o == nil {
			continue
		}
		out = append(out, o)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
