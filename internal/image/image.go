// Package image manages disk images for agent VM provisioning.
// A disk image contains a pre-built rootfs tarball with all packages
// pre-installed, enabling fast deployment via PXE boot.
package image

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/olljanat-ai/firewall4ai/internal/agent"
)

// BuildStatus represents the build state of an image version.
type BuildStatus string

const (
	BuildStatusPending  BuildStatus = "pending"
	BuildStatusBuilding BuildStatus = "building"
	BuildStatusReady    BuildStatus = "ready"
	BuildStatusError    BuildStatus = "error"
)

// ImageVersion represents a built version of a disk image.
type ImageVersion struct {
	Version   int         `json:"version"`
	Status    BuildStatus `json:"status"`
	StatusMsg string      `json:"status_msg"`
	Size      int64       `json:"size"`      // rootfs tarball size in bytes
	BuildLog  string      `json:"build_log"` // captured build output
	BuiltAt   time.Time   `json:"built_at"`
}

// AITool represents a pre-configured AI coding tool that can be installed.
type AITool string

const (
	AIToolOpenCode      AITool = "opencode"
	AIToolGitHubCopilot AITool = "github_copilot"
	AIToolClaudeCode    AITool = "claude_code"
	AIToolOpenAICodex   AITool = "openai_codex"
)

// ContainerTool represents a container runtime that can be installed.
type ContainerTool string

const (
	ContainerToolDocker     ContainerTool = "docker"
	ContainerToolNomad      ContainerTool = "nomad"
	ContainerToolKubernetes ContainerTool = "kubernetes"
)

// DiskImage represents a disk image configuration and its built versions.
type DiskImage struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	OS             agent.OSType    `json:"os"`              // alpine, debian, ubuntu
	OSVersion      string          `json:"os_version"`      // e.g., "3.23", "13"
	Packages       []string        `json:"packages"`        // packages to install in rootfs
	AITools        []AITool        `json:"ai_tools"`        // pre-configured AI coding tools to install
	ContainerTools []ContainerTool `json:"container_tools"` // container runtimes to install
	Scripts        []string        `json:"scripts"`         // custom shell script steps to run during build
	Versions       []ImageVersion  `json:"versions"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// LatestReadyVersion returns the highest version number with BuildStatusReady, or 0 if none.
func (img *DiskImage) LatestReadyVersion() int {
	best := 0
	for _, v := range img.Versions {
		if v.Status == BuildStatusReady && v.Version > best {
			best = v.Version
		}
	}
	return best
}

// NextVersion returns the next version number to use.
func (img *DiskImage) NextVersion() int {
	max := 0
	for _, v := range img.Versions {
		if v.Version > max {
			max = v.Version
		}
	}
	return max + 1
}

// Manager manages disk image configurations and their built versions.
type Manager struct {
	mu      sync.RWMutex
	images  map[string]*DiskImage
	dataDir string
}

// NewManager creates a new image manager.
func NewManager(dataDir string) *Manager {
	return &Manager{
		images:  make(map[string]*DiskImage),
		dataDir: dataDir,
	}
}

// ImagesDir returns the base directory for image storage.
func (m *Manager) ImagesDir() string {
	return filepath.Join(m.dataDir, "images")
}

// VersionDir returns the directory for a specific image version's files.
func (m *Manager) VersionDir(imageID string, version int) string {
	return filepath.Join(m.ImagesDir(), imageID, fmt.Sprintf("%d", version))
}

// RootfsPath returns the path to a version's rootfs tarball.
func (m *Manager) RootfsPath(imageID string, version int) string {
	return filepath.Join(m.VersionDir(imageID, version), "rootfs.tar.gz")
}

// LoadImages restores images from persisted state.
func (m *Manager) LoadImages(images []DiskImage) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range images {
		img := images[i]
		m.images[img.ID] = &img
	}
}

// ExportImages returns all images for persistence.
func (m *Manager) ExportImages() []DiskImage {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]DiskImage, 0, len(m.images))
	for _, img := range m.images {
		out = append(out, *img)
	}
	return out
}

// Add adds a new disk image. Returns error if ID already exists.
func (m *Manager) Add(img DiskImage) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.images[img.ID]; exists {
		return fmt.Errorf("image with ID %q already exists", img.ID)
	}

	now := time.Now()
	img.CreatedAt = now
	img.UpdatedAt = now
	if img.Versions == nil {
		img.Versions = []ImageVersion{}
	}
	m.images[img.ID] = &img
	return nil
}

// Update updates an existing disk image's configuration (not versions).
func (m *Manager) Update(img DiskImage) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, ok := m.images[img.ID]
	if !ok {
		return fmt.Errorf("image %q not found", img.ID)
	}

	img.CreatedAt = existing.CreatedAt
	img.Versions = existing.Versions
	img.UpdatedAt = time.Now()
	m.images[img.ID] = &img
	return nil
}

// Delete removes a disk image by ID. Also removes built files.
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.images[id]; !ok {
		return fmt.Errorf("image %q not found", id)
	}

	delete(m.images, id)

	// Remove built files.
	dir := filepath.Join(m.ImagesDir(), id)
	os.RemoveAll(dir)

	return nil
}

// Get returns a disk image by ID.
func (m *Manager) Get(id string) (*DiskImage, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	img, ok := m.images[id]
	if !ok {
		return nil, false
	}
	cp := *img
	cp.Versions = make([]ImageVersion, len(img.Versions))
	copy(cp.Versions, img.Versions)
	return &cp, true
}

// List returns all disk images.
func (m *Manager) List() []DiskImage {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]DiskImage, 0, len(m.images))
	for _, img := range m.images {
		cp := *img
		cp.Versions = make([]ImageVersion, len(img.Versions))
		copy(cp.Versions, img.Versions)
		out = append(out, cp)
	}
	return out
}

// AddVersion adds a new version entry to an image.
func (m *Manager) AddVersion(id string, ver ImageVersion) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	img, ok := m.images[id]
	if !ok {
		return fmt.Errorf("image %q not found", id)
	}

	img.Versions = append(img.Versions, ver)
	img.UpdatedAt = time.Now()
	return nil
}

// SetVersionStatus updates the status of a specific version.
func (m *Manager) SetVersionStatus(id string, version int, status BuildStatus, msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	img, ok := m.images[id]
	if !ok {
		return
	}

	for i := range img.Versions {
		if img.Versions[i].Version == version {
			img.Versions[i].Status = status
			img.Versions[i].StatusMsg = msg
			if status == BuildStatusReady {
				img.Versions[i].BuiltAt = time.Now()
				// Try to get file size.
				path := filepath.Join(m.ImagesDir(), id, fmt.Sprintf("%d", version), "rootfs.tar.gz")
				if info, err := os.Stat(path); err == nil {
					img.Versions[i].Size = info.Size()
				}
			}
			break
		}
	}
	img.UpdatedAt = time.Now()
}

// SetVersionBuildLog sets the build log for a specific version.
func (m *Manager) SetVersionBuildLog(id string, version int, log string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	img, ok := m.images[id]
	if !ok {
		return
	}
	for i := range img.Versions {
		if img.Versions[i].Version == version {
			img.Versions[i].BuildLog = log
			break
		}
	}
}

// DeleteVersion removes a specific version from an image.
func (m *Manager) DeleteVersion(id string, version int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	img, ok := m.images[id]
	if !ok {
		return fmt.Errorf("image %q not found", id)
	}

	for i := range img.Versions {
		if img.Versions[i].Version == version {
			img.Versions = append(img.Versions[:i], img.Versions[i+1:]...)
			break
		}
	}
	img.UpdatedAt = time.Now()

	// Remove built files.
	dir := filepath.Join(m.ImagesDir(), id, fmt.Sprintf("%d", version))
	os.RemoveAll(dir)

	return nil
}

// Count returns the total number of disk images.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.images)
}
