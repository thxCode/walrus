package webserver

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/seal-io/walrus/pkg/server/webserver/clis"
	"github.com/seal-io/walrus/pkg/server/webserver/identify"
	"github.com/seal-io/walrus/pkg/server/webserver/loopback"
	"github.com/seal-io/walrus/pkg/server/webserver/swagger"
	"github.com/seal-io/walrus/pkg/server/webserver/ui"
)

func Index() http.Handler {
	r := mux.NewRouter()

	clis.Route(r.PathPrefix("/clis").Methods(http.MethodGet))
	swagger.Route(r.PathPrefix("/swagger").Methods(http.MethodGet))
	identify.Route(r.PathPrefix("/identify"))
	loopback.Route(r.PathPrefix("/loopback"))
	r.NotFoundHandler = ui.Index()

	return r
}
