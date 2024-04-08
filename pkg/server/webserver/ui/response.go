package ui

import (
	"errors"
	"net/http"

	"github.com/seal-io/utils/httpx"
	"github.com/seal-io/utils/stringx"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ResponseErrorWithCode responds in JSON with the given status code and error message.
func ResponseErrorWithCode(w http.ResponseWriter, code int, err error) {
	s := meta.Status{
		TypeMeta: meta.TypeMeta{
			APIVersion: "meta.k8s.io/v1",
			Kind:       "Status",
		},
		Status: meta.StatusFailure,
		Reason: meta.StatusReason(stringx.TrimAllSpace(http.StatusText(code))),
		Code:   int32(code),
	}
	if err != nil {
		s.Message = err.Error()
	}

	httpx.JSON(w, code, s)
}

// ResponseError is similar to ResponseErrorWithCode,
// but it analyzes the error and responds with the appropriate status code and error message.
func ResponseError(w http.ResponseWriter, err error) {
	rerr := errors.Unwrap(err)
	switch {
	case kerrors.IsInvalid(rerr):
		ResponseErrorWithCode(w, http.StatusBadRequest, err)
	case kerrors.IsBadRequest(rerr):
		ResponseErrorWithCode(w, http.StatusBadRequest, err)
	case kerrors.IsNotFound(rerr):
		ResponseErrorWithCode(w, http.StatusBadRequest, err)
	case kerrors.IsUnauthorized(rerr):
		ResponseErrorWithCode(w, http.StatusUnauthorized, err)
	default:
		ResponseErrorWithCode(w, http.StatusInternalServerError, err)
	}
}

// RedirectErrorWithCode redirects to the error page with the given status code and error message.
func RedirectErrorWithCode(w http.ResponseWriter, code int, err error) {
	s := meta.Status{
		TypeMeta: meta.TypeMeta{
			APIVersion: "meta.k8s.io/v1",
			Kind:       "Status",
		},
		Status: meta.StatusFailure,
		Reason: meta.StatusReason(stringx.TrimAllSpace(http.StatusText(code))),
		Code:   int32(code),
	}
	if err != nil {
		s.Message = err.Error()
	}

	// TODO(thxCode): redirect to error page
	httpx.JSON(w, code, s)
}

// RedirectError is similar to RedirectErrorWithCode,
// but it analyzes the error and redirects to the error page with the appropriate status code and error message.
func RedirectError(w http.ResponseWriter, err error) {
	rerr := errors.Unwrap(err)
	switch {
	case kerrors.IsInvalid(rerr):
		RedirectErrorWithCode(w, http.StatusBadRequest, err)
	case kerrors.IsBadRequest(rerr):
		RedirectErrorWithCode(w, http.StatusBadRequest, err)
	case kerrors.IsNotFound(rerr):
		RedirectErrorWithCode(w, http.StatusBadRequest, err)
	case kerrors.IsUnauthorized(rerr):
		RedirectErrorWithCode(w, http.StatusUnauthorized, err)
	default:
		RedirectErrorWithCode(w, http.StatusInternalServerError, err)
	}
}
