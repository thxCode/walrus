package walrus

import (
	"context"
	"time"

	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlcli "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlpredicate "sigs.k8s.io/controller-runtime/pkg/predicate"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	walrus "github.com/seal-io/walrus/pkg/apis/walrus/v1"
	"github.com/seal-io/walrus/pkg/controller"
	"github.com/seal-io/walrus/pkg/systemauthz"
	"github.com/seal-io/walrus/pkg/systemkuberes"
)

// EnvironmentAuthzReconciler reconciles a v1.Environment object,
// and ensures the corresponding v1.ProjectSubjects' permissions are granted.
type EnvironmentAuthzReconciler struct {
	Client ctrlcli.Client
}

var _ ctrlreconcile.Reconciler = (*EnvironmentAuthzReconciler)(nil)

func (r *EnvironmentAuthzReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := ctrllog.FromContext(ctx)

	// Fetch.
	env := new(walrus.Environment)
	err := r.Client.Get(ctx, req.NamespacedName, env)
	if err != nil {
		logger.Error(err, "fetch environment")
		return ctrl.Result{}, ctrlcli.IgnoreNotFound(err)
	}

	// Skip deletion.
	if env.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}

	// Get project subjects.
	projSubjs := new(walrus.ProjectSubjects)
	{
		proj := &walrus.Project{
			ObjectMeta: meta.ObjectMeta{
				Namespace: systemkuberes.SystemNamespaceName,
				Name:      env.Namespace,
			},
		}
		err = r.Client.Get(ctx, ctrlcli.ObjectKeyFromObject(proj), proj)
		if err != nil {
			logger.Error(err, "get project")
			return ctrl.Result{}, err
		}
		err = r.Client.SubResource("subjects").Get(ctx, proj, projSubjs)
		if err != nil {
			logger.Error(err, "get project subjects")
			return ctrl.Result{}, err
		}
	}

	err = systemauthz.GrantProjectSubjectsToEnvironment(ctx, r.Client, projSubjs, env)
	if err != nil {
		logger.Error(err, "grant project subjects to environment, requeue")
		return ctrl.Result{RequeueAfter: time.Second}, err
	}

	return ctrl.Result{}, nil
}

func (r *EnvironmentAuthzReconciler) SetupController(_ context.Context, opts controller.SetupOptions) error {
	r.Client = opts.Manager.GetClient()

	// Filter out deletion events.
	p := ctrlpredicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			return e.ObjectNew.GetDeletionTimestamp() == nil
		},
		DeleteFunc: func(_ event.DeleteEvent) bool {
			return false
		},
	}

	return ctrl.NewControllerManagedBy(opts.Manager).
		For(&walrus.Environment{}).
		WithEventFilter(p).
		Complete(r)
}
