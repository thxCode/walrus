package systemauthz

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/seal-io/utils/stringx"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	authnuser "k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	ctrlcli "sigs.k8s.io/controller-runtime/pkg/client"

	walrus "github.com/seal-io/walrus/pkg/apis/walrus/v1"
	"github.com/seal-io/walrus/pkg/kubeclientset"
	"github.com/seal-io/walrus/pkg/kubemeta"
	"github.com/seal-io/walrus/pkg/systemmeta"
)

// ConvertClusterRoleNameFromProjectRole converts the cluster role name from the project subject role.
func ConvertClusterRoleNameFromProjectRole(role walrus.ProjectRole) (clusterRoleName string) {
	switch role {
	case walrus.ProjectRoleOwner:
		return AdminClusterRoleName
	case walrus.ProjectRoleMember:
		return EditorClusterRoleName
	default:
		return ViewerClusterRoleName
	}
}

// ConvertProjectRoleFromClusterRoleName converts the project role from the cluster role name.
//
// If the cluster role name is not recognized, it returns an empty string.
func ConvertProjectRoleFromClusterRoleName(clusterRoleName string) (role walrus.ProjectRole) {
	switch clusterRoleName {
	case AdminClusterRoleName:
		return walrus.ProjectRoleOwner
	case EditorClusterRoleName:
		return walrus.ProjectRoleMember
	case ViewerClusterRoleName:
		return walrus.ProjectRoleViewer
	}
	return ""
}

// GrantProjectSubjects (re)grants the given project role to the corresponding subjects.
func GrantProjectSubjects(ctx context.Context, cli ctrlcli.Client, projSubjs *walrus.ProjectSubjects) error {
	if projSubjs == nil || len(projSubjs.Items) == 0 {
		return nil
	}

	for i := range projSubjs.Items {
		item := &projSubjs.Items[i]

		eRb := &rbac.RoleBinding{
			ObjectMeta: meta.ObjectMeta{
				Namespace: projSubjs.Name,
				Name:      getProjectSubjectRoleBindingName(&item.SubjectRef),
			},
			RoleRef: rbac.RoleRef{
				APIGroup: rbac.GroupName,
				Kind:     "ClusterRole",
				Name:     ConvertClusterRoleNameFromProjectRole(item.Role),
			},
			Subjects: []rbac.Subject{
				{
					Kind:      rbac.ServiceAccountKind,
					Namespace: item.Namespace,
					Name:      ConvertServiceAccountNameFromSubjectName(item.Name),
				},
				{
					APIGroup: rbac.GroupName,
					Kind:     rbac.UserKind,
					Name:     ConvertImpersonateUserFromSubjectName(item.Namespace, item.Name),
				},
			},
		}
		systemmeta.NoteResource(eRb, "rolebindings", map[string]string{
			"project": kubemeta.GetNamespacedNameKey(projSubjs),
		})

		// Create.
		_, err := kubeclientset.CreateWithCtrlClient(ctx, cli, eRb,
			kubeclientset.WithRecreateIfDuplicated(kubeclientset.NewRbacRoleBindingCompareFunc(eRb)))
		if err != nil {
			return fmt.Errorf("create role binding: %w", err)
		}
	}

	return nil
}

// GrantProjectSubjectsToEnvironment (re)grants the given project role to the corresponding subjects under an environment.
func GrantProjectSubjectsToEnvironment(ctx context.Context, cli ctrlcli.Client, projSubjs *walrus.ProjectSubjects, env *walrus.Environment) error {
	if projSubjs == nil || len(projSubjs.Items) == 0 {
		return nil
	}

	for i := range projSubjs.Items {
		item := &projSubjs.Items[i]

		// NB(thxCode): Degrade the project role if the subject is a viewer but the environment is production.
		{
			subj := new(walrus.Subject)
			err := cli.Get(ctx, item.ToNamespacedName(), subj)
			if err != nil {
				return fmt.Errorf("get subject: %w", err)
			}
			if env.Spec.Type == walrus.EnvironmentTypeProduction && subj.Spec.Role == walrus.SubjectRoleViewer {
				item.Role = walrus.ProjectRoleViewer
			}
		}

		eRb := &rbac.RoleBinding{
			ObjectMeta: meta.ObjectMeta{
				Namespace: env.Name,
				Name:      getProjectSubjectRoleBindingName(&item.SubjectRef),
			},
			RoleRef: rbac.RoleRef{
				APIGroup: rbac.GroupName,
				Kind:     "ClusterRole",
				Name:     ConvertClusterRoleNameFromProjectRole(item.Role),
			},
			Subjects: []rbac.Subject{
				{
					Kind:      rbac.ServiceAccountKind,
					Namespace: item.Namespace,
					Name:      ConvertServiceAccountNameFromSubjectName(item.Name),
				},
				{
					APIGroup: rbac.GroupName,
					Kind:     rbac.UserKind,
					Name:     ConvertImpersonateUserFromSubjectName(item.Namespace, item.Name),
				},
			},
		}
		systemmeta.NoteResource(eRb, "rolebindings", map[string]string{
			"environment": kubemeta.GetNamespacedNameKey(env),
		})

		// Create.
		_, err := kubeclientset.CreateWithCtrlClient(ctx, cli, eRb,
			kubeclientset.WithRecreateIfDuplicated(kubeclientset.NewRbacRoleBindingCompareFunc(eRb)))
		if err != nil {
			return fmt.Errorf("create role binding: %w", err)
		}
	}

	return nil
}

// RevokeProjectSubjects revokes the project role from the corresponding subjects.
func RevokeProjectSubjects(ctx context.Context, cli ctrlcli.Client, projSubjs *walrus.ProjectSubjects) error {
	if projSubjs == nil || len(projSubjs.Items) == 0 {
		return nil
	}

	for i := range projSubjs.Items {
		item := &projSubjs.Items[i]

		eRb := &rbac.RoleBinding{
			ObjectMeta: meta.ObjectMeta{
				Namespace: projSubjs.Name,
				Name:      getProjectSubjectRoleBindingName(&item.SubjectRef),
			},
		}

		// Delete.
		err := kubeclientset.DeleteWithCtrlClient(ctx, cli, eRb)
		if err != nil {
			return fmt.Errorf("delete role binding: %w", err)
		}
	}

	return nil
}

// GrantProjectSubjectRole (re)grants the given project role for the request user.
func GrantProjectSubjectRole(ctx context.Context, cli ctrlcli.Client, proj *walrus.Project, role walrus.ProjectRole) error {
	ui, ok := genericapirequest.UserFrom(ctx)
	if !ok {
		return errors.New("request user not found")
	}

	// Don't bind the system:admin user or system:master group.
	if ui.GetName() == "system:admin" ||
		slices.Contains(ui.GetGroups(), "system:master") {
		return nil
	}

	return GrantProjectSubjectRoleFor(ctx, cli, proj, role, ui)
}

// GrantProjectSubjectRoleFor (re)grants the given for the specified user.
func GrantProjectSubjectRoleFor(ctx context.Context, cli ctrlcli.Client, proj *walrus.Project, role walrus.ProjectRole, user authnuser.Info) error { // nolint:lll
	// Validate.
	if proj == nil || proj.Name == "" {
		return errors.New("empty project")
	}
	if err := role.Validate(); err != nil {
		return err
	}

	// Convert.
	subjNamespace, subjName := ConvertSubjectNamesFromAuthnUser(user)
	if subjNamespace == "" || subjName == "" {
		return errors.New("incomplete user")
	}

	eRb := &rbac.RoleBinding{
		ObjectMeta: meta.ObjectMeta{
			Namespace: proj.Name,
			Name: getProjectSubjectRoleBindingName(&walrus.SubjectRef{
				Namespace: subjNamespace,
				Name:      subjName,
			}),
		},
		RoleRef: rbac.RoleRef{
			APIGroup: rbac.GroupName,
			Kind:     "ClusterRole",
			Name:     ConvertClusterRoleNameFromProjectRole(role),
		},
		Subjects: []rbac.Subject{
			{
				APIGroup: rbac.GroupName,
				Kind:     rbac.ServiceAccountKind,
				Name:     ConvertServiceAccountNameFromSubjectName(subjName),
			},
			{
				APIGroup: rbac.GroupName,
				Kind:     rbac.UserKind,
				Name:     ConvertImpersonateUserFromSubjectName(subjNamespace, subjName),
			},
		},
	}
	systemmeta.NoteResource(eRb, "rolebindings", map[string]string{
		"project": kubemeta.GetNamespacedNameKey(proj),
	})

	// Create.
	_, err := kubeclientset.CreateWithCtrlClient(ctx, cli, eRb,
		kubeclientset.WithRecreateIfDuplicated(kubeclientset.NewRbacRoleBindingCompareFunc(eRb)))
	if err != nil {
		return fmt.Errorf("create role binding: %w", err)
	}
	return nil
}

func getProjectSubjectRoleBindingName(subj *walrus.SubjectRef) string {
	return fmt.Sprintf("walrus-project-subject-%s",
		stringx.SumByFNV64a(subj.Namespace, subj.Name))
}
