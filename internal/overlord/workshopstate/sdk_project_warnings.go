// Copyright (c) 2026 Canonical Ltd
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 3 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package workshopstate

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/canonical/workshop/internal/sdk"
	"github.com/canonical/workshop/internal/workshop"
)

var secretLikeProjectPaths = []string{
	// Environment and local shell configuration.
	".env",
	".env.local",
	".env.development",
	".env.development.local",
	".env.test",
	".env.test.local",
	".env.production",
	".env.production.local",
	".envrc",
	".flaskenv",

	// Package registries and package publishing credentials.
	".npmrc",
	".pnpmrc",
	".pypirc",
	".netrc",

	// Python package index configuration.
	"pip.conf",
	".pip/pip.conf",
	"pip/pip.conf",

	// Cloud provider credentials.
	".aws/credentials",
	".aws/config",
	".azure/credentials",
	".azure/accessTokens.json",
	".azure/azureProfile.json",
	".config/gcloud/application_default_credentials.json",
	".config/gcloud/credentials.db",
	".oci/config",
	".oci/oci_api_key.pem",
	".doctl/config.yaml",

	// Kubernetes, Docker, and registry authentication.
	".kube/config",
	".docker/config.json",
	".config/containers/auth.json",
	".config/helm/registry/config.json",

	// SSH private keys.
	".ssh/id_rsa",
	".ssh/id_dsa",
	".ssh/id_ecdsa",
	".ssh/id_ed25519",
	"id_rsa",
	"id_dsa",
	"id_ecdsa",
	"id_ed25519",

	// Terraform and IaC state/config files that commonly contain secrets.
	"terraform.tfvars",
	"terraform.tfvars.json",
	"terraform.tfstate",
	"terraform.tfstate.backup",
	".terraformrc",
	"terraform.rc",

	// Ansible / deployment secrets.
	".vault_pass",
	".vault_pass.txt",
	"vault_pass.txt",
	"group_vars/all/vault.yml",
	"group_vars/all/vault.yaml",

	// Framework-specific local secrets.
	"config/master.key",
	"config/secrets.yml",
	"config/database.yml",
	"local_settings.py",

	// Common explicit credential file names.
	"credentials",
	"credentials.json",
	"secrets.json",
	"secret.json",
	"tokens.json",
	"token.json",
	"auth.json",
}

var secretLikeProjectGlobs = []string{
	"*.pem",
	"*.key",
	"*.p12",
	"*.pfx",
	"*.tfvars",
	"*.tfstate",
	"*.tfstate.backup",
}

const maxWarningItems = 5

// WarnSdkProjectExposure records a user-facing warning when Store SDKs may run
// lifecycle hooks with access to common secret-like files in the mounted
// project directory.
//
// This warning is intentionally non-blocking and only checks file paths, not
// file contents.
func (w *WorkshopManager) WarnSdkProjectExposure(project workshop.Project, manifests []Manifest) {
	storeSDKs := storeSDKNames(manifests)
	if len(storeSDKs) == 0 {
		return
	}

	secretPaths := findSecretLikeProjectPaths(project.Path)
	if len(secretLikeProjectPaths) == 0 {
		return
	}

	w.state.Warnf(
		"Store SDKs %s may run lifecycle hooks with access to project files in %q. "+
			"Potentially sensitive local files were found: %s. "+
			"Review SDK trust before continuing.",
		summarizeList(storeSDKs, maxWarningItems),
		project.Path,
		summarizeList(secretPaths, maxWarningItems),
	)
}

func findSecretLikeProjectPaths(projectPath string) []string {
	var found []string

	for _, rel := range secretLikeProjectPaths {
		path := filepath.Join(projectPath, rel)

		info, err := os.Lstat(path)
		if err != nil {
			continue
		}

		if isWarningCandidate(info) {
			found = append(found, rel)
		}
	}

	for _, pattern := range secretLikeProjectGlobs {
		matches, err := filepath.Glob(filepath.Join(projectPath, pattern))
		if err != nil {
			continue
		}

		for _, match := range matches {
			info, err := os.Lstat(match)
			if err != nil {
				continue
			}
			if !isWarningCandidate(info) {
				continue
			}
			rel, err := filepath.Rel(projectPath, match)
			if err != nil {
				continue
			}
			found = append(found, rel)
		}
	}

	found = uniqueStrings(found)
	slices.Sort(found)
	return found
}

func storeSDKNames(manifests []Manifest) []string {
	seen := map[string]bool{}
	var names []string

	for _, manifest := range manifests {
		for _, sk := range manifest.Sdks {
			if sk.Source != sdk.StoreSource {
				continue
			}
			if seen[sk.Name] {
				continue
			}
			seen[sk.Name] = true
			names = append(names, sk.Name)
		}
	}

	slices.Sort(names)
	return names
}

func isWarningCandidate(info os.FileInfo) bool {
	return info.Mode().IsRegular() || info.IsDir() || info.Mode()&os.ModeSymlink != 0
}

func uniqueStrings(items []string) []string {
	seen := map[string]bool{}
	var unique []string

	for _, item := range items {
		if seen[item] {
			continue
		}
		seen[item] = true
		unique = append(unique, item)
	}
	return unique
}

func summarizeList(items []string, max int) string {
	if len(items) <= max {
		return quoteList(items)
	}

	return fmt.Sprintf("%s, and %d more", quoteList(items[:max]), len(items)-max)
}

func quoteList(items []string) string {
	quoted := make([]string, 0, len(items))
	for _, item := range items {
		quoted = append(quoted, fmt.Sprintf("%q", item))
	}
	return strings.Join(quoted, ", ")
}
