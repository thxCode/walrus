package builder

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/mod/modfile"
)

const generatedHeader = "// Code generated by \"walrus\", DO NOT EDIT."

type Config struct {
	// ProjectDir is the root path of the Go project.
	ProjectDir string

	// Project gains from the go.mod file of ProjectDir if blank.
	Project string

	// Header allows users to provide an optional header signature for
	// the generated files.
	// format: '// Code generated by "walrus", DO NOT EDIT.'.
	Header string

	// Domain specifies the domain to place the API groups,
	// defaults to "walrus.seal.io".
	Domain string

	// APIs specifies the paths to execute deepcopy-gen, crd-gen, openapi-gen .etc.
	APIs []string

	// ExtensionAPIs specifies the paths to execute apireg-gen .etc.
	ExtensionAPIs []string

	// Webhooks specifies the paths to execute webhook-gen .etc.
	Webhooks []string

	// ExternalAPIs specifies the external apis to integrate.
	ExternalAPIs []string

	// PluralExceptions specifies the plural form exceptions.
	PluralExceptions map[string]string

	// ProtoImports specifies the proto package for imports.
	ProtoImports []string
}

func (c *Config) ValidateAndDefault() error {
	if c.ProjectDir == "" {
		return errors.New("invalid config: project dir is blank")
	}

	if c.Project == "" {
		project, err := getProject(c.ProjectDir)
		if err != nil {
			return fmt.Errorf("invalid config: error project getting %w", err)
		}
		c.Project = project
	}

	if c.Header == "" {
		c.Header = generatedHeader
	}

	if c.Domain == "" {
		c.Domain = "walrus.seal.io"
	}

	return nil
}

func getProject(projectDir string) (string, error) {
	mfn := filepath.Join(projectDir, "go.mod")

	mfb, err := os.ReadFile(mfn)
	if err != nil {
		return "", fmt.Errorf("read the go.mod: %w", err)
	}

	mf, err := modfile.Parse(mfn, mfb, nil)
	if err != nil {
		return "", fmt.Errorf("parse the go.mod: %w", err)
	}

	return mf.Module.Mod.Path, nil
}
