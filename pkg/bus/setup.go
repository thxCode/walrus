package bus

import (
	"context"

	"github.com/seal-io/seal/pkg/bus/servicerevision"
	"github.com/seal-io/seal/pkg/bus/setting"
	"github.com/seal-io/seal/pkg/bus/template"
	"github.com/seal-io/seal/pkg/cron"
	"github.com/seal-io/seal/pkg/dao/model"
	"github.com/seal-io/seal/pkg/deployer/terraform"
	"github.com/seal-io/seal/pkg/templates"
)

type SetupOptions struct {
	ModelClient model.ClientSet
}

func Setup(ctx context.Context, opts SetupOptions) (err error) {
	// Service revision.
	err = servicerevision.AddSubscriber("terraform-sync-service-revision-status",
		terraform.SyncServiceRevisionStatus)
	if err != nil {
		return
	}

	// Template.
	err = template.AddSubscriber("sync-template-schema", templates.SchemaSync(opts.ModelClient).Do)
	if err != nil {
		return
	}

	// Setting.
	err = setting.AddSubscriber("cron-sync", cron.Sync)
	if err != nil {
		return
	}

	return
}
