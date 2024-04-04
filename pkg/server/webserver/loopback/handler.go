package loopback

import (
	"net/http"

	"github.com/gorilla/mux"
)

func Route(r *mux.Route) {
	r.Handler(proxy())
}

func proxy() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	})
}
