/*
   Copyright 2020 Docker Compose CLI authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package compose

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/compose-spec/compose-go/v2/loader"
	"github.com/compose-spec/compose-go/v2/types"
	"github.com/google/go-cmp/cmp"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"gotest.tools/v3/assert"

	"github.com/docker/compose/v5/internal"
	"github.com/docker/compose/v5/pkg/api"
)

func Test_createLayers(t *testing.T) {
	project, err := loader.LoadWithContext(t.Context(), types.ConfigDetails{
		WorkingDir:  "testdata/publish/",
		Environment: types.Mapping{},
		ConfigFiles: []types.ConfigFile{
			{
				Filename: "testdata/publish/compose.yaml",
			},
		},
	})
	assert.NilError(t, err)
	project.ComposeFiles = []string{"testdata/publish/compose.yaml"}

	service := &composeService{}
	layers, err := service.createLayers(t.Context(), project, api.PublishOptions{
		WithEnvironment: true,
	})
	assert.NilError(t, err)

	published := string(layers[0].Data)
	assert.Equal(t, published, `name: test
services:
  test:
    extends:
      file: f8f9ede3d201ec37d5a5e3a77bbadab79af26035e53135e19571f50d541d390c.yaml
      service: foo

  string:
    image: test
    env_file: 5efca9cdbac9f5394c6c2e2094b1b42661f988f57fcab165a0bf72b205451af3.env

  list:
    image: test
    env_file:
      - 5efca9cdbac9f5394c6c2e2094b1b42661f988f57fcab165a0bf72b205451af3.env

  mapping:
    image: test
    env_file:
      - path: 5efca9cdbac9f5394c6c2e2094b1b42661f988f57fcab165a0bf72b205451af3.env
`)

	expectedLayers := []v1.Descriptor{
		{
			MediaType: "application/vnd.docker.compose.file+yaml",
			Annotations: map[string]string{
				"com.docker.compose.file":    "compose.yaml",
				"com.docker.compose.version": internal.Version,
			},
		},
		{
			MediaType: "application/vnd.docker.compose.file+yaml",
			Annotations: map[string]string{
				"com.docker.compose.extends": "true",
				"com.docker.compose.file":    "f8f9ede3d201ec37d5a5e3a77bbadab79af26035e53135e19571f50d541d390c",
				"com.docker.compose.version": internal.Version,
			},
		},
		{
			MediaType: "application/vnd.docker.compose.envfile",
			Annotations: map[string]string{
				"com.docker.compose.envfile": "5efca9cdbac9f5394c6c2e2094b1b42661f988f57fcab165a0bf72b205451af3",
				"com.docker.compose.version": internal.Version,
			},
		},
	}
	assert.DeepEqual(t, expectedLayers, layers, cmp.FilterPath(func(path cmp.Path) bool {
		return !slices.Contains([]string{".Data", ".Digest", ".Size"}, path.String())
	}, cmp.Ignore()))
}

func Test_preChecks_sensitive_data_detected_decline(t *testing.T) {
	dir := t.TempDir()
	envPath := dir + "/secrets.env"
	secretData := `AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`
	err := os.WriteFile(envPath, []byte(secretData), 0o600)
	assert.NilError(t, err)

	project := &types.Project{
		Services: types.Services{
			"web": {
				Name:  "web",
				Image: "nginx",
				EnvFiles: []types.EnvFile{
					{Path: envPath, Required: true},
				},
			},
		},
	}

	declined := func(message string, defaultValue bool) (bool, error) {
		return false, nil
	}
	svc := &composeService{
		prompt: declined,
	}

	accept, err := svc.preChecks(t.Context(), project, api.PublishOptions{})
	assert.NilError(t, err)
	assert.Equal(t, accept, false)
}

func Test_checkEnvironmentVariables(t *testing.T) {
	tests := []struct {
		name              string
		composeYAML       string
		withEnv           bool
		wantErr           bool
		wantErrContains   []string
		wantErrNotContain []string
	}{
		{
			name: "literal inline env without --with-env is flagged",
			composeYAML: `name: test
services:
  serviceA:
    image: alpine:3.12
    environment:
      FOO: bar
`,
			withEnv:         false,
			wantErr:         true,
			wantErrContains: []string{`service "serviceA" has literal environment variable "FOO".`},
		},
		{
			name: "interpolated inline env is not flagged",
			composeYAML: `name: test
services:
  serviceA:
    image: alpine:3.12
    environment:
      TEST: "${SOMEVAR}"
`,
			withEnv: false,
			wantErr: false,
		},
		{
			name: "mixed literal and interpolated only flags literal",
			composeYAML: `name: test
services:
  serviceA:
    image: alpine:3.12
    environment:
      FOO: bar
      TEST: "${SOMEVAR}"
`,
			withEnv:         false,
			wantErr:         true,
			wantErrContains: []string{`service "serviceA" has literal environment variable "FOO".`},
			wantErrNotContain: []string{
				`literal environment variable "TEST"`,
			},
		},
		{
			name: "nil value (KEY without =) is not flagged",
			composeYAML: `name: test
services:
  serviceA:
    image: alpine:3.12
    environment:
      - KEY
`,
			withEnv: false,
			wantErr: false,
		},
		{
			name: "bare $VAR interpolation is not flagged",
			composeYAML: `name: test
services:
  serviceA:
    image: alpine:3.12
    environment:
      DB_HOST: $MYSQL_HOST
`,
			withEnv: false,
			wantErr: false,
		},
		{
			name: "config.environment is not flagged (it is a var name, not a value)",
			composeYAML: `name: test
services:
  serviceA:
    image: alpine:3.12
configs:
  myconfig:
    environment: HARDCODED
`,
			withEnv: false,
			wantErr: false,
		},
		{
			name: "config.content literal is flagged",
			composeYAML: `name: test
services:
  serviceA:
    image: alpine:3.12
configs:
  myconfig:
    content: |
      api_key=plaintext-secret
`,
			withEnv:         false,
			wantErr:         true,
			wantErrContains: []string{`has literal inline content.`},
		},
		{
			name: "config.content interpolated is not flagged",
			composeYAML: `name: test
services:
  serviceA:
    image: alpine:3.12
configs:
  myconfig:
    content: "key=${SECRET}"
`,
			withEnv: false,
			wantErr: false,
		},
		{
			name: "with --with-env literal is allowed",
			composeYAML: `name: test
services:
  serviceA:
    image: alpine:3.12
    environment:
      FOO: bar
`,
			withEnv: true,
			wantErr: false,
		},
		{
			name: "env_file is still flagged with the existing message",
			composeYAML: `name: test
services:
  serviceA:
    image: alpine:3.12
    env_file:
      - publish.env
`,
			withEnv:         false,
			wantErr:         true,
			wantErrContains: []string{`service "serviceA" has env_file declared.`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			composePath := filepath.Join(dir, "compose.yaml")
			err := os.WriteFile(composePath, []byte(tt.composeYAML), 0o600)
			assert.NilError(t, err)

			// also create env file referenced by env_file fixture so resolved load succeeds
			envPath := filepath.Join(dir, "publish.env")
			err = os.WriteFile(envPath, []byte("FOO=bar\n"), 0o600)
			assert.NilError(t, err)

			project, err := loader.LoadWithContext(t.Context(), types.ConfigDetails{
				WorkingDir:  dir,
				Environment: types.Mapping{},
				ConfigFiles: []types.ConfigFile{
					{Filename: composePath},
				},
			}, func(options *loader.Options) {
				options.SetProjectName("test", true)
			})
			assert.NilError(t, err)
			project.ComposeFiles = []string{composePath}

			svc := &composeService{}
			err = svc.checkEnvironmentVariables(t.Context(), project, api.PublishOptions{WithEnvironment: tt.withEnv})
			if !tt.wantErr {
				assert.NilError(t, err)
				return
			}
			assert.Assert(t, err != nil, "expected error, got nil")
			for _, want := range tt.wantErrContains {
				assert.Assert(t, strings.Contains(err.Error(), want),
					"expected error to contain %q, got: %v", want, err)
			}
			for _, notWant := range tt.wantErrNotContain {
				assert.Assert(t, !strings.Contains(err.Error(), notWant),
					"expected error not to contain %q, got: %v", notWant, err)
			}
			// preserve trailing block
			assert.Assert(t, strings.Contains(err.Error(),
				"To avoid leaking sensitive data, you must either explicitly allow the sending of environment variables by using the --with-env flag,\n"+
					"or remove sensitive data from your Compose configuration"),
				"expected trailing block, got: %v", err)
		})
	}
}

func Test_checkEnvironmentVariables_extends(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.yaml")
	err := os.WriteFile(basePath, []byte(`services:
  api-base:
    image: alpine:3.12
    environment:
      INHERITED_PASSWORD: toto
`), 0o600)
	assert.NilError(t, err)

	composePath := filepath.Join(dir, "compose.yaml")
	err = os.WriteFile(composePath, []byte(`name: test
services:
  api:
    extends:
      file: ./base.yaml
      service: api-base
`), 0o600)
	assert.NilError(t, err)

	project, err := loader.LoadWithContext(t.Context(), types.ConfigDetails{
		WorkingDir:  dir,
		Environment: types.Mapping{},
		ConfigFiles: []types.ConfigFile{
			{Filename: composePath},
		},
	}, func(options *loader.Options) {
		options.SetProjectName("test", true)
	})
	assert.NilError(t, err)
	project.ComposeFiles = []string{composePath}

	svc := &composeService{}
	err = svc.checkEnvironmentVariables(t.Context(), project, api.PublishOptions{})
	assert.Assert(t, err != nil, "expected error for inherited literal env var, got nil")
	assert.Assert(t, strings.Contains(err.Error(), `literal environment variable "INHERITED_PASSWORD"`),
		"expected error to mention inherited literal, got: %v", err)
}

func Test_checkEnvironmentVariables_extends_other_services(t *testing.T) {
	// base.yaml has a service that the child does NOT extend, but the parent
	// file is published as a separate OCI layer, so its literal envs leak too.
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.yaml")
	err := os.WriteFile(basePath, []byte(`services:
  api-base:
    image: alpine:3.12
    environment:
      INHERITED_PASSWORD: shared-toto
  unrelated:
    image: alpine:3.12
    environment:
      UNRELATED_SECRET: lonely-toto
`), 0o600)
	assert.NilError(t, err)

	composePath := filepath.Join(dir, "compose.yaml")
	err = os.WriteFile(composePath, []byte(`name: test
services:
  api:
    extends:
      file: ./base.yaml
      service: api-base
`), 0o600)
	assert.NilError(t, err)

	project, err := loader.LoadWithContext(t.Context(), types.ConfigDetails{
		WorkingDir:  dir,
		Environment: types.Mapping{},
		ConfigFiles: []types.ConfigFile{{Filename: composePath}},
	}, func(options *loader.Options) {
		options.SetProjectName("test", true)
	})
	assert.NilError(t, err)
	project.ComposeFiles = []string{composePath}

	svc := &composeService{}
	err = svc.checkEnvironmentVariables(t.Context(), project, api.PublishOptions{})
	assert.Assert(t, err != nil, "expected error, got nil")
	assert.Assert(t, strings.Contains(err.Error(), `"INHERITED_PASSWORD"`),
		"expected inherited literal to be flagged, got: %v", err)
	assert.Assert(t, strings.Contains(err.Error(), `"UNRELATED_SECRET"`),
		"expected non-extended parent literal to be flagged, got: %v", err)
}

func Test_checkEnvironmentVariables_extends_with_env_allows(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.yaml")
	err := os.WriteFile(basePath, []byte(`services:
  api-base:
    image: alpine:3.12
    environment:
      INHERITED_PASSWORD: toto
`), 0o600)
	assert.NilError(t, err)

	composePath := filepath.Join(dir, "compose.yaml")
	err = os.WriteFile(composePath, []byte(`name: test
services:
  api:
    extends:
      file: ./base.yaml
      service: api-base
`), 0o600)
	assert.NilError(t, err)

	project, err := loader.LoadWithContext(t.Context(), types.ConfigDetails{
		WorkingDir:  dir,
		Environment: types.Mapping{},
		ConfigFiles: []types.ConfigFile{{Filename: composePath}},
	}, func(options *loader.Options) {
		options.SetProjectName("test", true)
	})
	assert.NilError(t, err)
	project.ComposeFiles = []string{composePath}

	svc := &composeService{}
	err = svc.checkEnvironmentVariables(t.Context(), project, api.PublishOptions{WithEnvironment: true})
	assert.NilError(t, err, "with --with-env, extends literals must be allowed")
}

func Test_checkEnvironmentVariables_aggregates_multiple_literals(t *testing.T) {
	dir := t.TempDir()
	composePath := filepath.Join(dir, "compose.yaml")
	err := os.WriteFile(composePath, []byte(`name: test
services:
  api:
    image: alpine:3.12
    environment:
      DB_PASSWORD: toto
      API_KEY: foo
      DEBUG: "1"
`), 0o600)
	assert.NilError(t, err)

	project, err := loader.LoadWithContext(t.Context(), types.ConfigDetails{
		WorkingDir:  dir,
		Environment: types.Mapping{},
		ConfigFiles: []types.ConfigFile{{Filename: composePath}},
	}, func(options *loader.Options) {
		options.SetProjectName("test", true)
	})
	assert.NilError(t, err)
	project.ComposeFiles = []string{composePath}

	svc := &composeService{}
	err = svc.checkEnvironmentVariables(t.Context(), project, api.PublishOptions{})
	assert.Assert(t, err != nil, "expected error, got nil")
	// Aggregated form: one line per service listing all literal vars sorted.
	assert.Assert(t,
		strings.Contains(err.Error(), `service "api" has literal environment variables: "API_KEY", "DB_PASSWORD", "DEBUG".`),
		"expected aggregated message with sorted vars, got: %v", err)
	// Should NOT produce one line per variable.
	assert.Assert(t,
		!strings.Contains(err.Error(), `has literal environment variable "DB_PASSWORD".`),
		"expected aggregated form, not per-variable lines, got: %v", err)
}

func Test_publish_decline_returns_ErrCanceled(t *testing.T) {
	project := &types.Project{
		Services: types.Services{
			"web": {
				Name:  "web",
				Image: "nginx",
				Volumes: []types.ServiceVolumeConfig{
					{
						Type:   types.VolumeTypeBind,
						Source: "/host/path",
						Target: "/container/path",
					},
				},
			},
		},
	}

	declined := func(message string, defaultValue bool) (bool, error) {
		return false, nil
	}
	svc := &composeService{
		prompt: declined,
		events: &ignore{},
	}

	err := svc.publish(t.Context(), project, "docker.io/myorg/myapp:latest", api.PublishOptions{})
	assert.Assert(t, errors.Is(err, api.ErrCanceled),
		"expected api.ErrCanceled when user declines, got: %v", err)
}
