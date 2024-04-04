package httpx

import (
	"net/http"

	"github.com/seal-io/utils/json"
	"github.com/seal-io/utils/pools/bytespool"
)

func PureJSON(w http.ResponseWriter, code int, v any) {
	buf := bytespool.GetBuffer()
	defer bytespool.Put(buf)

	err := json.NewEncoder(buf).Encode(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(buf.Bytes())
}

func JSON(w http.ResponseWriter, code int, v any) {
	buf := bytespool.GetBuffer()
	defer bytespool.Put(buf)

	err := json.NewEncoder(buf).Encode(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write(buf.Bytes())
}
