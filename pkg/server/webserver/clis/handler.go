package clis

import (
	"fmt"
	"net/http"
	"path"
	"path/filepath"

	"github.com/gorilla/mux"
	"github.com/seal-io/utils/httpx"
	"github.com/seal-io/utils/osx"

	"github.com/seal-io/walrus/pkg/server/webserver/openapi"
	"github.com/seal-io/walrus/pkg/system"
)

func Route(r *mux.Route) openapi.Decorator {
	p, _ := r.GetPathTemplate()
	r.Handler(http.StripPrefix(p, index()))
	return getOpenapiDecorate(p)
}

func index() http.Handler {
	dir := system.SubLibDir("clis")

	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		reqFile := path.Base(r.URL.Path)
		locFile := filepath.Join(dir, reqFile)

		if !osx.ExistsFile(locFile) {
			httpx.Error(rw, http.StatusNotFound)
			return
		}

		rwh := rw.Header()
		rwh.Add("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, reqFile))
		rwh.Add("Content-Type", "application/octet-stream")

		http.ServeFile(rw, r, locFile)
	})
}
