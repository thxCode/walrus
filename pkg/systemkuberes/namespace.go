package systemkuberes

import (
	"context"
	"fmt"

	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/seal-io/walrus/pkg/clients/clientset"
	"github.com/seal-io/walrus/pkg/kubeclientset"
	"github.com/seal-io/walrus/pkg/kubeclientset/review"
	"github.com/seal-io/walrus/pkg/system"
)

// SystemNamespaceName is the name indicates which Kubernetes Namespace storing system resources.
const SystemNamespaceName = system.NamespaceName

// InstallSystemNamespace creates the system namespace.
func InstallSystemNamespace(ctx context.Context, cli clientset.Interface) error {
	err := review.CanDoCreate(ctx,
		cli.AuthorizationV1().SelfSubjectAccessReviews(),
		review.Simples{
			{
				Group:    core.SchemeGroupVersion.Group,
				Version:  core.SchemeGroupVersion.Version,
				Resource: "namespaces",
			},
		},
	)
	if err != nil {
		return err
	}

	nsCli := cli.CoreV1().Namespaces()
	ns := &core.Namespace{
		ObjectMeta: meta.ObjectMeta{
			Name: SystemNamespaceName,
		},
	}

	_, err = kubeclientset.Create(ctx, nsCli, ns)
	if err != nil {
		return fmt.Errorf("install namespace %q: %w", ns.GetName(), err)
	}

	return nil
}
