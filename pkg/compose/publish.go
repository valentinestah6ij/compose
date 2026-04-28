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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/DefangLabs/secret-detector/pkg/scanner"
	"github.com/DefangLabs/secret-detector/pkg/secrets"
	"github.com/compose-spec/compose-go/v2/loader"
	"github.com/compose-spec/compose-go/v2/types"
	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"

	"github.com/docker/compose/v5/internal/oci"
	"github.com/docker/compose/v5/pkg/api"
	"github.com/docker/compose/v5/pkg/compose/transform"
)

func (s *composeService) Publish(ctx context.Context, project *types.Project, repository string, options api.PublishOptions) error {
	return Run(ctx, func(ctx context.Context) error {
		return s.publish(ctx, project, repository, options)
	}, "publish", s.events)
}

//nolint:gocyclo
func (s *composeService) publish(ctx context.Context, project *types.Project, repository string, options api.PublishOptions) error {
	project, err := project.WithProfiles([]string{"*"})
	if err != nil {
		return err
	}
	accept, err := s.preChecks(ctx, project, options)
	if err != nil {
		return err
	}
	if !accept {
		return api.ErrCanceled
	}
	err = s.Push(ctx, project, api.PushOptions{IgnoreFailures: true, ImageMandatory: true})
	if err != nil {
		return err
	}

	layers, err := s.createLayers(ctx, project, options)
	if err != nil {
		return err
	}

	s.events.On(api.Resource{
		ID:     repository,
		Text:   "publishing",
		Status: api.Working,
	})
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logrus.Debug("publishing layers")
		for _, layer := range layers {
			indent, _ := json.MarshalIndent(layer, "", "  ")
			fmt.Println(string(indent))
		}
	}
	if !s.dryRun {
		named, err := reference.ParseDockerRef(repository)
		if err != nil {
			return err
		}

		var insecureRegistries []string
		if options.InsecureRegistry {
			insecureRegistries = append(insecureRegistries, reference.Domain(named))
		}

		resolver := oci.NewResolver(s.configFile(), insecureRegistries...)

		descriptor, err := oci.PushManifest(ctx, resolver, named, layers, options.OCIVersion)
		if err != nil {
			s.events.On(api.Resource{
				ID:     repository,
				Text:   "publishing",
				Status: api.Error,
			})
			return err
		}

		if options.Application {
			manifests := []v1.Descriptor{}
			for _, service := range project.Services {
				ref, err := reference.ParseDockerRef(service.Image)
				if err != nil {
					return err
				}

				manifest, err := oci.Copy(ctx, resolver, ref, named)
				if err != nil {
					return err
				}
				manifests = append(manifests, manifest)
			}

			descriptor.Data = nil
			index, err := json.Marshal(v1.Index{
				Versioned: specs.Versioned{SchemaVersion: 2},
				MediaType: v1.MediaTypeImageIndex,
				Manifests: manifests,
				Subject:   &descriptor,
				Annotations: map[string]string{
					"com.docker.compose.version": api.ComposeVersion,
				},
			})
			if err != nil {
				return err
			}
			imagesDescriptor := v1.Descriptor{
				MediaType:    v1.MediaTypeImageIndex,
				ArtifactType: oci.ComposeProjectArtifactType,
				Digest:       digest.FromString(string(index)),
				Size:         int64(len(index)),
				Annotations: map[string]string{
					"com.docker.compose.version": api.ComposeVersion,
				},
				Data: index,
			}
			err = oci.Push(ctx, resolver, reference.TrimNamed(named), imagesDescriptor)
			if err != nil {
				return err
			}
		}
	}
	s.events.On(api.Resource{
		ID:     repository,
		Text:   "published",
		Status: api.Done,
	})
	return nil
}

func (s *composeService) createLayers(ctx context.Context, project *types.Project, options api.PublishOptions) ([]v1.Descriptor, error) {
	var layers []v1.Descriptor
	extFiles := map[string]string{}
	envFiles := map[string]string{}
	for _, file := range project.ComposeFiles {
		data, err := processFile(ctx, file, project, extFiles, envFiles)
		if err != nil {
			return nil, err
		}

		layerDescriptor := oci.DescriptorForComposeFile(file, data)
		layers = append(layers, layerDescriptor)
	}

	extLayers, err := processExtends(ctx, project, extFiles)
	if err != nil {
		return nil, err
	}
	layers = append(layers, extLayers...)

	if options.WithEnvironment {
		layers = append(layers, envFileLayers(envFiles)...)
	}

	if options.ResolveImageDigests {
		yaml, err := s.generateImageDigestsOverride(ctx, project)
		if err != nil {
			return nil, err
		}

		layerDescriptor := oci.DescriptorForComposeFile("image-digests.yaml", yaml)
		layers = append(layers, layerDescriptor)
	}
	return layers, nil
}

func processExtends(ctx context.Context, project *types.Project, extFiles map[string]string) ([]v1.Descriptor, error) {
	var layers []v1.Descriptor
	moreExtFiles := map[string]string{}
	envFiles := map[string]string{}
	for xf, hash := range extFiles {
		data, err := processFile(ctx, xf, project, moreExtFiles, envFiles)
		if err != nil {
			return nil, err
		}

		layerDescriptor := oci.DescriptorForComposeFile(hash, data)
		layerDescriptor.Annotations["com.docker.compose.extends"] = "true"
		layers = append(layers, layerDescriptor)
	}
	for f, hash := range moreExtFiles {
		if _, ok := extFiles[f]; ok {
			delete(moreExtFiles, f)
		}
		extFiles[f] = hash
	}
	if len(moreExtFiles) > 0 {
		extLayers, err := processExtends(ctx, project, moreExtFiles)
		if err != nil {
			return nil, err
		}
		layers = append(layers, extLayers...)
	}
	return layers, nil
}

func processFile(ctx context.Context, file string, project *types.Project, extFiles map[string]string, envFiles map[string]string) ([]byte, error) {
	f, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	base, err := loader.LoadWithContext(ctx, types.ConfigDetails{
		WorkingDir:  project.WorkingDir,
		Environment: project.Environment,
		ConfigFiles: []types.ConfigFile{
			{
				Filename: file,
				Content:  f,
			},
		},
	}, func(options *loader.Options) {
		options.SkipValidation = true
		options.SkipExtends = true
		options.SkipConsistencyCheck = true
		options.ResolvePaths = true
		options.SkipInclude = true
		options.Profiles = project.Profiles
	})
	if err != nil {
		return nil, err
	}
	for name, service := range base.Services {
		for i, envFile := range service.EnvFiles {
			hash := fmt.Sprintf("%x.env", sha256.Sum256([]byte(envFile.Path)))
			envFiles[envFile.Path] = hash
			f, err = transform.ReplaceEnvFile(f, name, i, hash)
			if err != nil {
				return nil, err
			}
		}

		if service.Extends == nil {
			continue
		}
		xf := service.Extends.File
		if xf == "" {
			continue
		}
		if _, err = os.Stat(service.Extends.File); os.IsNotExist(err) {
			// No local file, while we loaded the project successfully: This is actually a remote resource
			continue
		}

		hash := fmt.Sprintf("%x.yaml", sha256.Sum256([]byte(xf)))
		extFiles[xf] = hash

		f, err = transform.ReplaceExtendsFile(f, name, hash)
		if err != nil {
			return nil, err
		}
	}
	return f, nil
}

func (s *composeService) generateImageDigestsOverride(ctx context.Context, project *types.Project) ([]byte, error) {
	project, err := project.WithImagesResolved(ImageDigestResolver(ctx, s.configFile(), s.apiClient()))
	if err != nil {
		return nil, err
	}
	override := types.Project{
		Services: types.Services{},
	}
	for name, service := range project.Services {
		override.Services[name] = types.ServiceConfig{
			Image: service.Image,
		}
	}
	return override.MarshalYAML()
}

func (s *composeService) preChecks(ctx context.Context, project *types.Project, options api.PublishOptions) (bool, error) {
	if ok, err := s.checkOnlyBuildSection(project); !ok || err != nil {
		return false, err
	}
	bindMounts := s.checkForBindMount(project)
	if len(bindMounts) > 0 {
		b := strings.Builder{}
		b.WriteString("you are about to publish bind mounts declaration within your OCI artifact.\n" +
			"only the bind mount declarations will be added to the OCI artifact (not content)\n" +
			"please double check that you are not mounting potential user's sensitive directories or data\n")
		for key, val := range bindMounts {
			b.WriteString(key)
			for _, v := range val {
				b.WriteString(v.String())
				b.WriteRune('\n')
			}
		}
		b.WriteString("Are you ok to publish these bind mount declarations?")
		confirm, err := s.prompt(b.String(), false)
		if err != nil || !confirm {
			return false, err
		}
	}
	detectedSecrets, err := s.checkForSensitiveData(ctx, project)
	if err != nil {
		return false, err
	}
	if len(detectedSecrets) > 0 {
		b := strings.Builder{}
		b.WriteString("you are about to publish sensitive data within your OCI artifact.\n" +
			"please double check that you are not leaking sensitive data\n")
		for _, val := range detectedSecrets {
			b.WriteString(val.Type)
			b.WriteRune('\n')
			fmt.Fprintf(&b, "%q: %s\n", val.Key, val.Value)
		}
		b.WriteString("Are you ok to publish these sensitive data?")
		confirm, err := s.prompt(b.String(), false)
		if err != nil || !confirm {
			return false, err
		}
	}
	err = s.checkEnvironmentVariables(ctx, project, options)
	if err != nil {
		return false, err
	}
	return true, nil
}

// serviceFindings tracks per-service evidence collected while walking
// every compose file scheduled for publication.
type serviceFindings struct {
	hasEnvFiles bool
	literalVars map[string]struct{}
}

// checkEnvironmentVariables walks every compose file that will be serialized
// into the OCI artifact (the top-level files plus any local extends parents)
// and flags services that contain hardcoded env_file declarations or literal
// environment values. Interpolated values like "${SECRET}" are preserved as
// placeholders in the published YAML and don't leak the resolved value, so
// they are intentionally not flagged.
func (s *composeService) checkEnvironmentVariables(ctx context.Context, project *types.Project, options api.PublishOptions) error {
	if options.WithEnvironment || len(project.ComposeFiles) == 0 {
		return nil
	}

	services, configsWithLiteralContent, err := collectEnvironmentFindings(ctx, project)
	if err != nil {
		return err
	}

	lines := buildEnvironmentErrorLines(services, configsWithLiteralContent)
	if len(lines) == 0 {
		return nil
	}

	var msg strings.Builder
	for _, l := range lines {
		fmt.Fprintf(&msg, "%s\n", l)
	}
	msg.WriteString("To avoid leaking sensitive data, you must either explicitly allow the sending of environment variables by using the --with-env flag,\n")
	msg.WriteString("or remove sensitive data from your Compose configuration")
	return errors.New(msg.String())
}

// collectEnvironmentFindings walks every compose file scheduled for
// publication (top-level files plus any local extends parents discovered along
// the way) and aggregates per-service and per-config findings. The walk order
// mirrors processExtends so coverage matches what is actually serialized into
// the OCI artifact.
func collectEnvironmentFindings(ctx context.Context, project *types.Project) (map[string]*serviceFindings, map[string]struct{}, error) {
	services := map[string]*serviceFindings{}
	configsWithLiteralContent := map[string]struct{}{}

	seen := map[string]struct{}{}
	queue := slices.Clone(project.ComposeFiles)
	for len(queue) > 0 {
		file := queue[0]
		queue = queue[1:]
		if _, ok := seen[file]; ok {
			continue
		}
		seen[file] = struct{}{}

		unresolved, err := loadUnresolvedFile(ctx, project, file)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load compose file %s: %w", file, err)
		}

		for _, service := range unresolved.Services {
			recordServiceFindings(services, service)
			if parent := localExtendsParent(service); parent != "" {
				queue = append(queue, parent)
			}
		}
		for _, config := range unresolved.Configs {
			// config.Environment is a variable *name* (only the name is
			// published, not its resolved value) so it is not a leak. Inline
			// config.Content is what ends up in the artifact. compose-go
			// enforces that file, environment, and content are mutually
			// exclusive.
			if config.Content != "" && !containsInterpolation(config.Content) {
				configsWithLiteralContent[config.Name] = struct{}{}
			}
		}
	}
	return services, configsWithLiteralContent, nil
}

func recordServiceFindings(services map[string]*serviceFindings, service types.ServiceConfig) {
	f := services[service.Name]
	if f == nil {
		f = &serviceFindings{literalVars: map[string]struct{}{}}
		services[service.Name] = f
	}
	if len(service.EnvFiles) > 0 {
		f.hasEnvFiles = true
	}
	for key, value := range service.Environment {
		if value != nil && !containsInterpolation(*value) {
			f.literalVars[key] = struct{}{}
		}
	}
}

// localExtendsParent returns the path of an extends parent file that exists on
// disk, or "" when the service does not extend or extends a remote resource.
func localExtendsParent(service types.ServiceConfig) string {
	if service.Extends == nil || service.Extends.File == "" {
		return ""
	}
	if _, err := os.Stat(service.Extends.File); err != nil {
		return ""
	}
	return service.Extends.File
}

// buildEnvironmentErrorLines renders one human-readable line per finding,
// aggregating multiple literal vars on the same service into a single line so
// real configurations don't produce a wall of text.
func buildEnvironmentErrorLines(services map[string]*serviceFindings, configsWithLiteralContent map[string]struct{}) []string {
	var lines []string
	for _, name := range sortedKeys(services) {
		f := services[name]
		if f.hasEnvFiles {
			lines = append(lines, fmt.Sprintf("service %q has env_file declared.", name))
		}
		if len(f.literalVars) > 0 {
			vars := sortedKeys(f.literalVars)
			if len(vars) == 1 {
				lines = append(lines, fmt.Sprintf("service %q has literal environment variable %q.", name, vars[0]))
			} else {
				quoted := make([]string, len(vars))
				for i, v := range vars {
					quoted[i] = fmt.Sprintf("%q", v)
				}
				lines = append(lines, fmt.Sprintf("service %q has literal environment variables: %s.", name, strings.Join(quoted, ", ")))
			}
		}
	}
	for _, name := range sortedKeys(configsWithLiteralContent) {
		lines = append(lines, fmt.Sprintf("config %q has literal inline content.", name))
	}
	return lines
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// interpolationPattern matches compose-spec interpolation tokens: ${VAR},
// ${VAR:-default}, $VAR, $_VAR. A `$$` escape is treated as containing
// interpolation (the second `$` followed by a name still matches), which
// keeps the heuristic simple and conservatively skips the value.
var interpolationPattern = regexp.MustCompile(`\$([A-Za-z_]\w*|\{[^}]+\})`)

func containsInterpolation(value string) bool {
	return interpolationPattern.MatchString(value)
}

// loadUnresolvedFile loads a single compose file with interpolation and
// environment resolution skipped, so callers can inspect raw user-provided
// values. Used by both checkEnvironmentVariables and composeFileAsByteReader.
func loadUnresolvedFile(ctx context.Context, project *types.Project, filePath string) (*types.Project, error) {
	return loader.LoadWithContext(ctx, types.ConfigDetails{
		WorkingDir:  project.WorkingDir,
		Environment: project.Environment,
		ConfigFiles: []types.ConfigFile{{Filename: filePath}},
	}, func(options *loader.Options) {
		options.SkipValidation = true
		options.SkipExtends = true
		options.SkipConsistencyCheck = true
		options.ResolvePaths = true
		// SkipInclude mirrors processFile: include directives stay symbolic in
		// the published artifact, so included content must not be inspected
		// here either (otherwise we'd flag literals that never ship).
		options.SkipInclude = true
		options.SkipInterpolation = true
		options.SkipResolveEnvironment = true
		options.Profiles = project.Profiles
	})
}

func envFileLayers(files map[string]string) []v1.Descriptor {
	var layers []v1.Descriptor
	for file, hash := range files {
		f, err := os.ReadFile(file)
		if err != nil {
			// if we can't read the file, skip to the next one
			continue
		}
		layerDescriptor := oci.DescriptorForEnvFile(hash, f)
		layers = append(layers, layerDescriptor)
	}
	return layers
}

func (s *composeService) checkOnlyBuildSection(project *types.Project) (bool, error) {
	errorList := []string{}
	for _, service := range project.Services {
		if service.Image == "" && service.Build != nil {
			errorList = append(errorList, service.Name)
		}
	}
	if len(errorList) > 0 {
		var errMsg strings.Builder
		errMsg.WriteString("your Compose stack cannot be published as it only contains a build section for service(s):\n")
		for _, serviceInError := range errorList {
			fmt.Fprintf(&errMsg, "- %q\n", serviceInError)
		}
		return false, errors.New(errMsg.String())
	}
	return true, nil
}

func (s *composeService) checkForBindMount(project *types.Project) map[string][]types.ServiceVolumeConfig {
	allFindings := map[string][]types.ServiceVolumeConfig{}
	for serviceName, config := range project.Services {
		bindMounts := []types.ServiceVolumeConfig{}
		for _, volume := range config.Volumes {
			if volume.Type == types.VolumeTypeBind {
				bindMounts = append(bindMounts, volume)
			}
		}
		if len(bindMounts) > 0 {
			allFindings[serviceName] = bindMounts
		}
	}
	return allFindings
}

func (s *composeService) checkForSensitiveData(ctx context.Context, project *types.Project) ([]secrets.DetectedSecret, error) {
	var allFindings []secrets.DetectedSecret
	scan := scanner.NewDefaultScanner()
	// Check all compose files
	for _, file := range project.ComposeFiles {
		in, err := composeFileAsByteReader(ctx, file, project)
		if err != nil {
			return nil, err
		}

		findings, err := scan.ScanReader(in)
		if err != nil {
			return nil, fmt.Errorf("failed to scan compose file %s: %w", file, err)
		}
		allFindings = append(allFindings, findings...)
	}
	for _, service := range project.Services {
		// Check env files
		for _, envFile := range service.EnvFiles {
			findings, err := scan.ScanFile(envFile.Path)
			if err != nil {
				return nil, fmt.Errorf("failed to scan env file %s: %w", envFile.Path, err)
			}
			allFindings = append(allFindings, findings...)
		}
	}

	// Check configs defined by files
	for _, config := range project.Configs {
		if config.File != "" {
			findings, err := scan.ScanFile(config.File)
			if err != nil {
				return nil, fmt.Errorf("failed to scan config file %s: %w", config.File, err)
			}
			allFindings = append(allFindings, findings...)
		}
	}

	// Check secrets defined by files
	for _, secret := range project.Secrets {
		if secret.File != "" {
			findings, err := scan.ScanFile(secret.File)
			if err != nil {
				return nil, fmt.Errorf("failed to scan secret file %s: %w", secret.File, err)
			}
			allFindings = append(allFindings, findings...)
		}
	}

	return allFindings, nil
}

func composeFileAsByteReader(ctx context.Context, filePath string, project *types.Project) (io.Reader, error) {
	base, err := loadUnresolvedFile(ctx, project, filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load compose file %s: %w", filePath, err)
	}
	in, err := base.MarshalYAML()
	if err != nil {
		return nil, err
	}
	return bytes.NewBuffer(in), nil
}
