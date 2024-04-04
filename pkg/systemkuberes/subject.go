package systemkuberes

import (
	"context"
	"fmt"

	"github.com/seal-io/utils/osx"
	"github.com/seal-io/utils/stringx"
	core "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"

	walrus "github.com/seal-io/walrus/pkg/apis/walrus/v1"
	"github.com/seal-io/walrus/pkg/clients/clientset"
	"github.com/seal-io/walrus/pkg/kubeclientset"
	"github.com/seal-io/walrus/pkg/kubeclientset/review"
	"github.com/seal-io/walrus/pkg/systemsetting"
)

// AdminSubjectName is the name of the admin subject.
const AdminSubjectName = "admin"

// InstallAdminSubject creates the admin subject,
// alias to Kubernetes Secret walrus-subject-admin under the system namespace.
func InstallAdminSubject(ctx context.Context, cli clientset.Interface, password string) error {
	err := review.CanDoCreate(ctx,
		cli.AuthorizationV1().SelfSubjectAccessReviews(),
		review.Simples{
			{
				Group:    core.SchemeGroupVersion.Group,
				Version:  core.SchemeGroupVersion.Version,
				Resource: "secrets",
			},
			{
				Group:    walrus.SchemeGroupVersion.Group,
				Version:  walrus.SchemeGroupVersion.Version,
				Resource: "subjects",
			},
		},
	)
	if err != nil {
		return err
	}

	subCli := cli.WalrusV1().Subjects(SystemNamespaceName)
	_, err = subCli.Get(ctx, AdminSubjectName, meta.GetOptions{ResourceVersion: "0"})
	if err != nil && kerrors.IsNotFound(err) && password == "" {
		// NB(thxCode): in order to avoid multiple Walrus get different bootstrap password,
		// we will save the bootstrap password to the Kubernetes Secret walrus-subject-admin-bootstrap-password.
		randomPwd := stringx.RandomString(16)
		secCli := cli.CoreV1().Secrets(SystemNamespaceName)
		sec := &core.Secret{
			ObjectMeta: meta.ObjectMeta{
				Namespace: SystemNamespaceName,
				Name:      "walrus-subject-admin-bootstrap-password",
			},
			StringData: map[string]string{
				"password": randomPwd,
			},
		}
		sec, err := kubeclientset.Create(ctx, secCli, sec)
		if err != nil {
			return fmt.Errorf("create random bootstrap password secret: %w", err)
		}

		// Update the bootstrap password provision if the random password has been accepted.
		if randomPwd == string(sec.Data["password"]) {
			provision := "process"
			switch {
			case osx.ExistEnv("KUBERNETES_SERVICE_HOST"):
				provision = "kubernetes"
			case osx.ExistEnv("_RUNNING_INSIDE_CONTAINER_"):
				provision = "docker"
			}
			_ = systemsetting.BootstrapPasswordProvision.Configure(ctx, provision)
		}

		password = string(sec.Data["password"])

		// Print out.
		klog.Infof("!!! Bootstrap Admin Password: %s !!!", password)
	}

	// Return if the admin subject already exists.
	if err == nil {
		return nil
	}

	// Create subject.
	subj := &walrus.Subject{
		ObjectMeta: meta.ObjectMeta{
			Namespace: SystemNamespaceName,
			Name:      AdminSubjectName,
		},
		Spec: walrus.SubjectSpec{
			Provider:    DefaultSubjectProviderName,
			Role:        walrus.SubjectRoleAdmin,
			DisplayName: "Administrator",
			Description: "The administrator subject created by Walrus.",
			Email:       "info@seal.io",
			Credential:  ptr.To(password),
		},
	}

	_, err = kubeclientset.Create(ctx, subCli, subj)
	if err != nil {
		return fmt.Errorf("install admin subject: %w", err)
	}

	return nil
}
