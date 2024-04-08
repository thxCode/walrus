package clis

import (
	"path"

	"github.com/seal-io/utils/json"
	"github.com/seal-io/utils/stringx"
	openspec3 "k8s.io/kube-openapi/pkg/spec3"

	"github.com/seal-io/walrus/pkg/server/webserver/openapi"
)

func getOpenapiDecorate(prefix string) openapi.Decorator {
	return func(spec *openspec3.OpenAPI) *openspec3.OpenAPI {
		decoratePaths(spec, prefix)
		return spec
	}
}

func decoratePaths(spec *openspec3.OpenAPI, prefix string) {
	if spec.Paths == nil {
		spec.Paths = &openspec3.Paths{
			Paths: map[string]*openspec3.Path{},
		}
	}

	decorateGetBinaryPath(spec.Paths, prefix)
}

func decorateGetBinaryPath(spec *openspec3.Paths, prefix string) {
	pJson := `
{
    "get": {
        "tags": [
            "CommandLineInterface"
        ],
        "description": "download Command Line Interface(CLI) binary",
        "operationId": "downloadCliBinary",
        "parameters": [
            {
                "name": "binary",
                "in": "path",
                "description": "binary name to download",
                "required": true,
                "schema": {
                    "type": "string",
                    "uniqueItems": true
                }
            }
        ],
        "responses": {
            "200": {
                "description": "OK",
                "content": {
                    "application/octet-stream": {
                        "schema": {
                            "format": "byte",
                            "type": "string"
                        }
                    }
                }
            }
        }
    }
}
`

	p := new(openspec3.Path)
	json.MustUnmarshal(stringx.ToBytes(&pJson), p)
	spec.Paths[path.Join(prefix, "{binary}")] = p
}
