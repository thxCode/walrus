package walrus

import (
	"context"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	ctrlcli "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlpredicate "sigs.k8s.io/controller-runtime/pkg/predicate"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	walrus "github.com/seal-io/walrus/pkg/apis/walrus/v1"
	"github.com/seal-io/walrus/pkg/controller"
	"github.com/seal-io/walrus/pkg/systemauthz"
)

// SubjectAuthzReconciler reconciles a v1.Subject object,
// and ensures its permissions are granted.
type SubjectAuthzReconciler struct {
	Client ctrlcli.Client
}

var _ ctrlreconcile.Reconciler = (*SubjectAuthzReconciler)(nil)

func (r *SubjectAuthzReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := ctrllog.FromContext(ctx)

	// Fetch.
	subj := new(walrus.Subject)
	err := r.Client.Get(ctx, req.NamespacedName, subj)
	if err != nil {
		logger.Error(err, "fetch subject")
		return ctrl.Result{}, ctrlcli.IgnoreNotFound(err)
	}

	// Skip deletion.
	if subj.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}

	// Grant.
	err = systemauthz.GrantSubject(ctx, r.Client, subj)
	if err != nil {
		logger.Error(err, "grant subject, requeue")
		return ctrl.Result{RequeueAfter: time.Second}, err
	}

	return ctrl.Result{}, nil
}

func (r *SubjectAuthzReconciler) SetupController(_ context.Context, opts controller.SetupOptions) error {
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
		For(&walrus.Subject{}).
		WithEventFilter(p).
		Complete(r)
}
