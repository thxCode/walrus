package resource

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"

	"github.com/seal-io/walrus/pkg/auths/session"
	"github.com/seal-io/walrus/pkg/dao"
	"github.com/seal-io/walrus/pkg/dao/model"
	"github.com/seal-io/walrus/pkg/dao/model/resource"
	"github.com/seal-io/walrus/pkg/dao/model/resourcecomponent"
	"github.com/seal-io/walrus/pkg/dao/model/resourcerelationship"
	"github.com/seal-io/walrus/pkg/dao/types"
	"github.com/seal-io/walrus/pkg/dao/types/object"
	"github.com/seal-io/walrus/pkg/dao/types/status"
	deptypes "github.com/seal-io/walrus/pkg/deployer/types"
	"github.com/seal-io/walrus/utils/errorx"
	"github.com/seal-io/walrus/utils/log"
	"github.com/seal-io/walrus/utils/strs"
)

const annotationSubjectIDName = "walrus.seal.io/subject-id"

// Options for deploy or destroy.
type Options struct {
	Deployer deptypes.Deployer
}

func Create(
	ctx context.Context,
	mc model.ClientSet,
	entity *model.Resource,
	opts Options,
) (*model.ResourceOutput, error) {
	err := mc.WithTx(ctx, func(tx *model.Tx) (err error) {
		// TODO(thxCode): generated by entc.
		status.ResourceStatusDeployed.Unknown(entity, "")
		entity.Status.SetSummary(status.WalkResource(&entity.Status))

		entity, err = tx.Resources().Create().
			Set(entity).
			SaveE(ctx, dao.ResourceDependenciesEdgeSave)

		return err
	})
	if err != nil {
		return nil, err
	}

	ready, err := CheckDependencyStatus(ctx, mc, opts.Deployer, entity)
	if err != nil {
		return nil, err
	}

	// Resource dependency ready can be applied promptly.
	if ready {
		// Deploy resource.
		err = Apply(ctx, mc, entity, opts)
		if err != nil {
			return nil, err
		}
	}

	return model.ExposeResource(entity), nil
}

func UpdateStatus(
	ctx context.Context,
	mc model.ClientSet,
	entity *model.Resource,
) error {
	entity.Status.SetSummary(status.WalkResource(&entity.Status))

	err := mc.Resources().UpdateOne(entity).
		SetStatus(entity.Status).
		Exec(ctx)
	if err != nil && !model.IsNotFound(err) {
		return err
	}

	return nil
}

func Apply(
	ctx context.Context,
	mc model.ClientSet,
	entity *model.Resource,
	opts Options,
) (err error) {
	logger := log.WithName("resource")

	if !status.ResourceStatusDeployed.IsUnknown(entity) {
		return errorx.Errorf("resource status is not deploying, resource: %s", entity.ID)
	}

	err = opts.Deployer.Apply(ctx, mc, entity, deptypes.ApplyOptions{})
	if err != nil {
		err = fmt.Errorf("failed to apply resource: %w", err)
		logger.Error(err)

		// Update a failure status.
		status.ResourceStatusDeployed.False(entity, err.Error())

		err = UpdateStatus(ctx, mc, entity)
		if err != nil {
			logger.Errorf("error updating status of resource %s: %v", entity.ID, err)
		}
	}

	return nil
}

func Destroy(
	ctx context.Context,
	mc model.ClientSet,
	entity *model.Resource,
	opts Options,
) (err error) {
	logger := log.WithName("resource")

	// If no resource component exists, skip calling deployer destroy and do straight deletion.
	exist, err := mc.ResourceComponents().Query().
		Where(resourcecomponent.ResourceID(entity.ID)).
		Exist(ctx)
	if err != nil {
		return err
	}

	if !exist {
		return mc.Resources().DeleteOneID(entity.ID).Exec(ctx)
	}

	updateFailedStatus := func(err error) {
		status.ResourceStatusDeleted.False(entity, err.Error())

		err = UpdateStatus(ctx, mc, entity)
		if err != nil {
			logger.Errorf("error updating status of resource %s: %v", entity.ID, err)
		}
	}

	// Check dependants.
	dependants, err := dao.GetResourceDependantNames(ctx, mc, entity)
	if err != nil {
		updateFailedStatus(err)
		return err
	}

	if len(dependants) > 0 {
		msg := fmt.Sprintf("Waiting for dependants to be deleted: %s", strs.Join(", ", dependants...))
		if !status.ResourceStatusProgressing.IsUnknown(entity) ||
			status.ResourceStatusDeleted.GetMessage(entity) != msg {
			// Mark status to deleting with dependency message.
			status.ResourceStatusDeleted.Reset(entity, msg)
			status.ResourceStatusProgressing.Unknown(entity, "")

			if err = UpdateStatus(ctx, mc, entity); err != nil {
				return fmt.Errorf("failed to update resource status: %w", err)
			}
		}

		return nil
	} else {
		// Mark status to deleting.
		status.ResourceStatusDeleted.Reset(entity, "")
		status.ResourceStatusProgressing.True(entity, "Resolved dependencies")

		if err = UpdateStatus(ctx, mc, entity); err != nil {
			return fmt.Errorf("failed to update resource status: %w", err)
		}
	}

	err = opts.Deployer.Destroy(ctx, mc, entity, deptypes.DestroyOptions{})
	if err != nil {
		log.Errorf("fail to destroy resource: %w", err)

		updateFailedStatus(err)
	}

	return nil
}

// Stop stops given resource.
func Stop(
	ctx context.Context,
	mc model.ClientSet,
	entity *model.Resource,
	opts Options,
) (err error) {
	logger := log.WithName("resource")

	updateFailedStatus := func(err error) {
		status.ResourceStatusStopped.False(entity, err.Error())

		err = UpdateStatus(ctx, mc, entity)
		if err != nil {
			logger.Errorf("error updating status of resource %s: %v", entity.ID, err)
		}
	}

	// Check dependants.
	dependants, err := dao.GetResourceDependantNames(ctx, mc, entity, status.ResourceStatusStopped.String())
	if err != nil {
		updateFailedStatus(err)
		return err
	}

	if len(dependants) > 0 {
		msg := fmt.Sprintf("Waiting for dependants to be stopped: %s", strs.Join(", ", dependants...))
		if !status.ResourceStatusProgressing.IsUnknown(entity) ||
			status.ResourceStatusStopped.GetMessage(entity) != msg {
			// Mark status to stopping with dependency message.
			status.ResourceStatusStopped.Reset(entity, "")
			status.ResourceStatusProgressing.Unknown(entity, msg)

			if err = UpdateStatus(ctx, mc, entity); err != nil {
				return fmt.Errorf("failed to update resource status: %w", err)
			}
		}

		return nil
	} else {
		// Mark status to stopping.
		status.ResourceStatusStopped.Reset(entity, "")
		status.ResourceStatusProgressing.True(entity, "Resolved dependencies")

		if err = UpdateStatus(ctx, mc, entity); err != nil {
			return fmt.Errorf("failed to update resource status: %w", err)
		}
	}

	err = opts.Deployer.Destroy(ctx, mc, entity, deptypes.DestroyOptions{})
	if err != nil {
		log.Errorf("fail to destroy resource: %w", err)

		updateFailedStatus(err)
	}

	return nil
}

func GetSubjectID(entity *model.Resource) (object.ID, error) {
	if entity == nil {
		return "", fmt.Errorf("resource is nil")
	}

	subjectIDStr := entity.Annotations[annotationSubjectIDName]

	return object.ID(subjectIDStr), nil
}

func SetSubjectID(ctx context.Context, resources ...*model.Resource) error {
	sj, err := session.GetSubject(ctx)
	if err != nil {
		return err
	}

	for i := range resources {
		if resources[i].Annotations == nil {
			resources[i].Annotations = make(map[string]string)
		}
		resources[i].Annotations[annotationSubjectIDName] = string(sj.ID)
	}

	return nil
}

// SetResourceStatusScheduled sets the status of the resources to scheduled.
func SetResourceStatusScheduled(
	ctx context.Context,
	mc model.ClientSet,
	dp deptypes.Deployer,
	entities ...*model.Resource,
) error {
	for i := range entities {
		if entities[i] == nil {
			return fmt.Errorf("resource is nil")
		}
		dependencyNames := dao.ResourceRelationshipGetDependencyNames(entities[i])

		msg := ""
		if len(dependencyNames) > 0 {
			msg = fmt.Sprintf("Waiting for dependent resources to be ready: %s", strs.Join(", ", dependencyNames...))
			status.ResourceStatusProgressing.Reset(entities[i], msg)
		} else {
			status.ResourceStatusDeployed.Reset(entities[i], "")
		}

		entities[i].Status.SetSummary(status.WalkResource(&entities[i].Status))

		entity, err := mc.Resources().UpdateOne(entities[i]).
			SetStatus(entities[i].Status).
			Save(ctx)
		if err != nil {
			return err
		}

		if len(dependencyNames) > 0 {
			continue
		}

		err = Apply(ctx, mc, entity, Options{
			Deployer: dp,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

// CreateDraftResources creates un-deployed resources but do no deployment.
// TODO refactor and coordinate with CreateScheduledResources.
func CreateDraftResources(
	ctx context.Context,
	mc model.ClientSet,
	entities ...*model.Resource,
) (model.Resources, error) {
	results := make(model.Resources, 0, len(entities))

	sortedResources, err := TopologicalSortResources(entities)
	if err != nil {
		return nil, err
	}

	err = mc.WithTx(ctx, func(tx *model.Tx) error {
		for i := range sortedResources {
			entity := sortedResources[i]

			status.ResourceStatusUnDeployed.True(entity, "Draft")
			entity.Status.SetSummary(status.WalkResource(&entity.Status))

			entity, err = tx.Resources().Create().
				Set(entity).
				SaveE(ctx, dao.ResourceDependenciesEdgeSave)
			if err != nil {
				return err
			}

			results = append(results, entity)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return results, nil
}

// CreateScheduledResources creates scheduled resources.
func CreateScheduledResources(
	ctx context.Context,
	mc model.ClientSet,
	dp deptypes.Deployer,
	entities model.Resources,
) (model.Resources, error) {
	results := make(model.Resources, 0, len(entities))

	sortedResources, err := TopologicalSortResources(entities)
	if err != nil {
		return nil, err
	}

	for i := range sortedResources {
		entity := sortedResources[i]

		err = mc.WithTx(ctx, func(tx *model.Tx) error {
			// TODO(thxCode): generated by entc.
			status.ResourceStatusDeployed.Unknown(entity, "")
			entity.Status.SetSummary(status.WalkResource(&entity.Status))

			entity, err = tx.Resources().Create().
				Set(entity).
				SaveE(ctx, dao.ResourceDependenciesEdgeSave)
			if err != nil {
				return err
			}

			return SetResourceStatusScheduled(ctx, tx, dp, entity)
		})
		if err != nil {
			return nil, err
		}

		results = append(results, entity)
	}

	return results, nil
}

// IsStatusReady returns true if the resource is ready.
func IsStatusReady(entity *model.Resource) bool {
	switch entity.Status.SummaryStatus {
	case "Preparing", "NotReady", "Ready":
		return true
	}

	return false
}

// IsStatusFalse returns true if the resource is in error status.
func IsStatusFalse(entity *model.Resource) bool {
	switch entity.Status.SummaryStatus {
	case "DeployFailed", "DeleteFailed":
		return true
	case "Progressing":
		return entity.Status.Error
	}

	return false
}

// IsStatusDeleted returns true if the resource is deleted.
func IsStatusDeleted(entity *model.Resource) bool {
	switch entity.Status.SummaryStatus {
	case "Deleted", "Deleting":
		return true
	}

	return false
}

const (
	summaryStatusDeploying   = "Deploying"
	summaryStatusProgressing = "Progressing"
)

// CheckDependencyStatus check resource dependencies status is ready to apply.
func CheckDependencyStatus(
	ctx context.Context,
	mc model.ClientSet,
	dp deptypes.Deployer,
	entity *model.Resource,
) (bool, error) {
	// Check dependants.
	dependencies, err := mc.ResourceRelationships().Query().
		Where(
			resourcerelationship.ResourceID(entity.ID),
			resourcerelationship.DependencyIDNEQ(entity.ID),
		).
		QueryDependency().
		Select(resource.FieldID).
		Where(
			resource.Or(
				func(s *sql.Selector) {
					s.Where(sqljson.ValueEQ(
						resource.FieldStatus,
						summaryStatusDeploying,
						sqljson.Path("summaryStatus"),
					))
				},
				resource.And(
					func(s *sql.Selector) {
						s.Where(sqljson.ValueEQ(
							resource.FieldStatus,
							summaryStatusProgressing,
							sqljson.Path("summaryStatus"),
						))
					},
					func(s *sql.Selector) {
						s.Where(sqljson.ValueEQ(
							resource.FieldStatus,
							true,
							sqljson.Path("transitioning"),
						))
					},
				),
			),
		).
		All(ctx)
	if err != nil {
		return false, err
	}

	if len(dependencies) > 0 {
		// If dependency resources is in deploying status.
		err = SetResourceStatusScheduled(ctx, mc, dp, entity)
		if err != nil {
			return false, err
		}

		return false, nil
	}

	return true, nil
}

// IsService tells if the given resource is of service type.
func IsService(r *model.Resource) bool {
	if r == nil {
		return false
	}

	return r.TemplateID != nil
}

// IsStoppable tells whether the given resource is stoppable.
func IsStoppable(r *model.Resource) bool {
	if r == nil {
		return false
	}

	if r.Labels[types.LabelResourceStoppable] == "true" ||
		(r.TemplateID != nil && r.Labels[types.LabelResourceStoppable] != "false") {
		return true
	}

	return false
}

// CanBeStopped tells whether the given resource can be stopped.
func CanBeStopped(r *model.Resource) bool {
	return status.ResourceStatusDeployed.IsTrue(r)
}

// IsInactive tells whether the given resource is inactive.
func IsInactive(r *model.Resource) bool {
	if r == nil {
		return false
	}

	return r.Status.SummaryStatus == status.ResourceStatusUnDeployed.String() ||
		r.Status.SummaryStatus == status.ResourceStatusStopped.String()
}
