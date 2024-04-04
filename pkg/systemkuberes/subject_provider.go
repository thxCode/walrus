package systemkuberes

import (
	"context"
	"fmt"

	meta "k8s.io/apimachinery/pkg/apis/meta/v1"

	walrus "github.com/seal-io/walrus/pkg/apis/walrus/v1"
	"github.com/seal-io/walrus/pkg/clients/clientset"
	"github.com/seal-io/walrus/pkg/kubeclientset"
	"github.com/seal-io/walrus/pkg/kubeclientset/review"
)

// DefaultSubjectProviderName is the name of the default subject provider.
const DefaultSubjectProviderName = "default"

// InstallDefaultSubjectProvider creates the default subject provider,
// alias to Kubernetes Secret walrus-subject-provider-default under the system namespace.
func InstallDefaultSubjectProvider(ctx context.Context, cli clientset.Interface) error {
	err := review.CanDoCreate(ctx,
		cli.AuthorizationV1().SelfSubjectAccessReviews(),
		review.Simples{
			{
				Group:    walrus.SchemeGroupVersion.Group,
				Version:  walrus.SchemeGroupVersion.Version,
				Resource: "subjectproviders",
			},
		},
	)
	if err != nil {
		return err
	}

	subjProvCli := cli.WalrusV1().SubjectProviders(SystemNamespaceName)
	subjProv := &walrus.SubjectProvider{
		ObjectMeta: meta.ObjectMeta{
			Namespace: SystemNamespaceName,
			Name:      DefaultSubjectProviderName,
		},
		Spec: walrus.SubjectProviderSpec{
			Type:        walrus.SubjectProviderTypeInternal,
			DisplayName: "Default Subject Provider",
			Description: "The default subject provider created by Walrus.",
		},
	}

	_, err = kubeclientset.Create(ctx, subjProvCli, subjProv)
	if err != nil {
		return fmt.Errorf("install default subject provider: %w", err)
	}

	return nil
}
