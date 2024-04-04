package systemauthz

import (
	"context"
	"fmt"
	"strings"

	"github.com/seal-io/utils/stringx"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	authnuser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/utils/ptr"
	ctrlcli "sigs.k8s.io/controller-runtime/pkg/client"

	walrus "github.com/seal-io/walrus/pkg/apis/walrus/v1"
	"github.com/seal-io/walrus/pkg/kubeclientset"
	"github.com/seal-io/walrus/pkg/kubemeta"
	"github.com/seal-io/walrus/pkg/systemmeta"
)

// ConvertImpersonateUserFromSubjectName converts the subject {namespace,name} pair to an impersonate user.
func ConvertImpersonateUserFromSubjectName(subjNamespace, subjName string) (impersonateUser string) {
	return "walrus:" + subjNamespace + ":" + subjName
}

// ConvertSubjectNamesFromImpersonateUser converts the impersonate user to the subject {namespace,name} pair.
//
// If the impersonate user is not a subject-delegated impersonate user,
// it returns empty strings.
func ConvertSubjectNamesFromImpersonateUser(impersonateUser string) (subjNamespace, subjName string) {
	subjNamespace, subjName, ok := strings.Cut(strings.TrimPrefix(impersonateUser, "walrus:"), ":")
	if ok && subjNamespace != "" && subjName != "" {
		return subjNamespace, subjName
	}
	return "", ""
}

// ConvertServiceAccountNameFromSubjectName converts the subject name to a service account name.
func ConvertServiceAccountNameFromSubjectName(subjName string) (saName string) {
	return "walrus-subject-" + subjName
}

// ConvertSubjectNameFromServiceAccountName converts the service account name to a subject name.
//
// If the service account name is not a subject-delegated service account name,
// it returns an empty string.
func ConvertSubjectNameFromServiceAccountName(saName string) (subjName string) {
	subjName = strings.TrimPrefix(saName, "walrus-subject-")
	if subjName != saName {
		return subjName
	}
	return ""
}

// ConvertSubjectNamesFromAuthnUser converts the authentication user to the subject {namespace,name} pair.
//
// If the authentication user is not a subject-delegated authentication user(impersonate user or service account),
// it returns empty strings.
func ConvertSubjectNamesFromAuthnUser(user authnuser.Info) (subjNamespace, subjName string) {
	un := user.GetName()
	switch {
	default:
		return "", ""
	case strings.HasPrefix(un, "walrus:"):
		return ConvertSubjectNamesFromImpersonateUser(un)
	case strings.HasPrefix(un, "system:serviceaccount:"):
	}
	subjNamespace, subjName, ok := strings.Cut(strings.TrimPrefix(un, "system:serviceaccount:"), ":")
	if ok {
		subjName = ConvertSubjectNameFromServiceAccountName(subjName)
	}
	if subjNamespace != "" && subjName != "" {
		return subjNamespace, subjName
	}
	return "", ""
}

// GrantSubject (re)grants the role of the subject for the subject.
func GrantSubject(ctx context.Context, cli ctrlcli.Client, subj *walrus.Subject) error {
	n := getSubjectRoleBindingName(subj)
	imName := ConvertImpersonateUserFromSubjectName(subj.Namespace, subj.Name)
	saName := ConvertServiceAccountNameFromSubjectName(subj.Name)

	// Private role and role binding.
	eP := []ctrlcli.Object{
		&rbac.Role{
			ObjectMeta: meta.ObjectMeta{
				Namespace: subj.Namespace,
				Name:      fmt.Sprintf("%s-selfreview", n),
			},
			Rules: []rbac.PolicyRule{
				{
					APIGroups: []string{
						walrus.GroupName,
					},
					Resources: []string{
						"subjects",
					},
					ResourceNames: []string{
						subj.Name,
					},
					Verbs: []string{
						"get",
						"update",
						"patch",
					},
				},
				{
					APIGroups: []string{
						walrus.GroupName,
					},
					Resources: []string{
						"subjects/login",
						"subjects/token",
					},
					ResourceNames: []string{
						subj.Name,
					},
					Verbs: []string{
						"create",
					},
				},
			},
		},
		&rbac.RoleBinding{
			ObjectMeta: meta.ObjectMeta{
				Namespace: subj.Namespace,
				Name:      fmt.Sprintf("%s-selfreview", n),
			},
			RoleRef: rbac.RoleRef{
				APIGroup: rbac.GroupName,
				Kind:     "Role",
				Name:     fmt.Sprintf("%s-selfreview", n),
			},
			Subjects: []rbac.Subject{
				{
					Kind:      rbac.ServiceAccountKind,
					Namespace: subj.Namespace,
					Name:      saName,
				},
				{
					APIGroup: rbac.GroupName,
					Kind:     rbac.UserKind,
					Name:     imName,
				},
			},
		},
	}
	for i := range eP {
		// Create.
		kubemeta.ControlOnWithoutBlock(eP[i], subj, walrus.SchemeGroupVersion.WithKind("Subject"))
		_, err := kubeclientset.CreateWithCtrlClient(ctx, cli, eP[i])
		if err != nil {
			return fmt.Errorf("create role or role binding: %w", err)
		}
	}

	// Public role binding.
	switch subj.Spec.Role {
	case walrus.SubjectRoleManager:
		eRb := &rbac.RoleBinding{
			ObjectMeta: meta.ObjectMeta{
				Namespace: subj.Namespace,
				Name:      n,
			},
			RoleRef: rbac.RoleRef{
				APIGroup: rbac.GroupName,
				Kind:     "ClusterRole",
				Name:     EditorClusterRoleName,
			},
			Subjects: []rbac.Subject{
				{
					Kind:      rbac.ServiceAccountKind,
					Namespace: subj.Namespace,
					Name:      saName,
				},
				{
					APIGroup: rbac.GroupName,
					Kind:     rbac.UserKind,
					Name:     imName,
				},
			},
		}
		systemmeta.NoteResource(eRb, "rolebindings", nil)

		// Create.
		kubemeta.ControlOnWithoutBlock(eRb, subj, walrus.SchemeGroupVersion.WithKind("Subject"))
		_, err := kubeclientset.CreateWithCtrlClient(ctx, cli, eRb,
			kubeclientset.WithRecreateIfDuplicated(kubeclientset.NewRbacRoleBindingCompareFunc(eRb)))
		if err != nil {
			return fmt.Errorf("create role binding: %w", err)
		}
		return nil
	case walrus.SubjectRoleAdmin:
		eCrb := &rbac.ClusterRoleBinding{
			ObjectMeta: meta.ObjectMeta{
				Name: n,
			},
			RoleRef: rbac.RoleRef{
				APIGroup: rbac.GroupName,
				Kind:     "ClusterRole",
				Name:     AdminClusterRoleName,
			},
			Subjects: []rbac.Subject{
				{
					Kind:      rbac.ServiceAccountKind,
					Namespace: subj.Namespace,
					Name:      saName,
				},
				{
					APIGroup: rbac.GroupName,
					Kind:     rbac.UserKind,
					Name:     imName,
				},
			},
		}
		systemmeta.NoteResource(eCrb, "rolebindings", nil)

		// Create.
		kubemeta.ControlOnWithoutBlock(eCrb, subj, walrus.SchemeGroupVersion.WithKind("Subject"))
		_, err := kubeclientset.CreateWithCtrlClient(ctx, cli, eCrb,
			kubeclientset.WithRecreateIfDuplicated(kubeclientset.NewRbacClusterRoleBindingCompareFunc(eCrb)))
		if err != nil {
			return fmt.Errorf("create cluster role binding: %w", err)
		}
		return nil
	}

	return nil
}

// RevokeSubject revokes the role of the subject from the subject.
func RevokeSubject(ctx context.Context, cli ctrlcli.Client, subj *walrus.Subject) error {
	n := getSubjectRoleBindingName(subj)

	switch subj.Spec.Role {
	case walrus.SubjectRoleManager:
		eRb := &rbac.RoleBinding{
			ObjectMeta: meta.ObjectMeta{
				Namespace: subj.Namespace,
				Name:      n,
			},
		}

		// Delete.
		return kubeclientset.DeleteWithCtrlClient(ctx, cli, eRb,
			kubeclientset.WithDeleteMetaOptions(meta.DeleteOptions{
				PropagationPolicy: ptr.To(meta.DeletePropagationForeground),
			}))
	case walrus.SubjectRoleAdmin:
		eCrb := &rbac.ClusterRoleBinding{
			ObjectMeta: meta.ObjectMeta{
				Name: n,
			},
		}

		// Delete.
		return kubeclientset.DeleteWithCtrlClient(ctx, cli, eCrb,
			kubeclientset.WithDeleteMetaOptions(meta.DeleteOptions{
				PropagationPolicy: ptr.To(meta.DeletePropagationForeground),
			}))
	}

	return nil
}

func getSubjectRoleBindingName(subj *walrus.Subject) string {
	return fmt.Sprintf("walrus-subject-%s",
		stringx.SumByFNV64a(subj.Namespace, subj.Name))
}
