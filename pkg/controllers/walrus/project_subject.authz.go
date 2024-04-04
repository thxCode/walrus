package walrus

import (
	"context"
	"time"

	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlcli "sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlpredicate "sigs.k8s.io/controller-runtime/pkg/predicate"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	walrus "github.com/seal-io/walrus/pkg/apis/walrus/v1"
	"github.com/seal-io/walrus/pkg/controller"
	walrusext "github.com/seal-io/walrus/pkg/extensionapis/walrus"
	"github.com/seal-io/walrus/pkg/kubemeta"
	"github.com/seal-io/walrus/pkg/systemauthz"
	"github.com/seal-io/walrus/pkg/systemmeta"
)

// ProjectSubjectAuthzReconciler reconciles a rbac RoleBinding object,
// and ensures the corresponding v1.ProjectSubject's permissions are granted to the related environment.
type ProjectSubjectAuthzReconciler struct {
	Client ctrlcli.Client
}

var _ ctrlreconcile.Reconciler = (*ProjectSubjectAuthzReconciler)(nil)

func (r *ProjectSubjectAuthzReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := ctrllog.FromContext(ctx)

	// Fetch.
	rb := new(rbac.RoleBinding)
	err := r.Client.Get(ctx, req.NamespacedName, rb)
	if err != nil {
		logger.Error(err, "fetch role binding")
		return ctrl.Result{}, ctrlcli.IgnoreNotFound(err)
	}

	// Skip deletion.
	if rb.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}

	// Convert.
	projSubj := walrusext.ConvertProjectSubjectFromRoleBinding(rb)
	if projSubj == nil {
		return ctrl.Result{}, nil
	}

	// Get the related project.
	projKey := kubemeta.ParseNamespacedNameKey(systemmeta.DescribeResourceNote(rb, "project"))
	proj := &walrus.Project{
		ObjectMeta: meta.ObjectMeta{
			Namespace: projKey.Namespace,
			Name:      projKey.Name,
		},
	}
	err = r.Client.Get(ctx, ctrlcli.ObjectKeyFromObject(proj), proj)
	if err != nil {
		logger.Error(err, "get related project")
		return ctrl.Result{}, ctrlcli.IgnoreNotFound(err)
	}
	if proj.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}

	// Convert project subjects from a role binding.
	projSubjs := &walrus.ProjectSubjects{
		ObjectMeta: proj.ObjectMeta,
		Items:      []walrus.ProjectSubject{*projSubj},
	}

	// List the related environment.
	envList := new(walrus.EnvironmentList)
	err = r.Client.List(ctx, envList, ctrlcli.InNamespace(proj.Name))
	if err != nil {
		logger.Error(err, "list related environments")
		return ctrl.Result{}, err
	}

	// Copy to all related environments.
	for _, env := range envList.Items {
		if env.DeletionTimestamp != nil {
			continue
		}

		err = systemauthz.GrantProjectSubjectsToEnvironment(ctx, r.Client, projSubjs, ptr.To(env))
		if err != nil {
			logger.Error(err, "grant project subjects to environment, requeue")
			return ctrl.Result{RequeueAfter: time.Second}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *ProjectSubjectAuthzReconciler) SetupController(_ context.Context, opts controller.SetupOptions) error {
	r.Client = opts.Manager.GetClient()

	// Filter out non-project role bindings.
	p := ctrlpredicate.NewPredicateFuncs(func(obj ctrlcli.Object) bool {
		resType := systemmeta.DescribeResourceType(obj)
		if resType != "rolebindings" {
			return false
		}
		return kubemeta.ContainsNameInNamespacedNameKey(obj.GetNamespace(),
			systemmeta.DescribeResourceNote(obj, "project"))
	})

	return ctrl.NewControllerManagedBy(opts.Manager).
		For(&rbac.RoleBinding{}).
		WithEventFilter(p).
		Complete(r)
}
