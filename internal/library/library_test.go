package library

import (
	"testing"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/config"
)

func TestRepoForHost(t *testing.T) {
	repos := []config.PackageRepoConfig{
		{Name: "Debian", Type: "debian", Hosts: []string{"deb.debian.org", "security.debian.org"}},
		{Name: "Go Modules", Type: "golang", Hosts: []string{"proxy.golang.org", "sum.golang.org"}},
		{Name: "npm", Type: "npm", Hosts: []string{"registry.npmjs.org"}},
		{Name: "PyPI", Type: "pypi", Hosts: []string{"pypi.org", "files.pythonhosted.org"}},
		{Name: "NuGet", Type: "nuget", Hosts: []string{"api.nuget.org"}},
	}

	tests := []struct {
		host string
		want string
	}{
		{"deb.debian.org", "Debian"},
		{"security.debian.org", "Debian"},
		{"proxy.golang.org", "Go Modules"},
		{"sum.golang.org", "Go Modules"},
		{"registry.npmjs.org", "npm"},
		{"pypi.org", "PyPI"},
		{"files.pythonhosted.org", "PyPI"},
		{"api.nuget.org", "NuGet"},
		{"example.com", ""},
		{"npmjs.org", ""},
	}
	for _, tt := range tests {
		repo := RepoForHost(tt.host, repos)
		if tt.want == "" {
			if repo != nil {
				t.Errorf("RepoForHost(%q) = %q, want nil", tt.host, repo.Name)
			}
		} else {
			if repo == nil {
				t.Errorf("RepoForHost(%q) = nil, want %q", tt.host, tt.want)
			} else if repo.Name != tt.want {
				t.Errorf("RepoForHost(%q) = %q, want %q", tt.host, repo.Name, tt.want)
			}
		}
	}
}

func TestParsePackageName_Debian(t *testing.T) {
	tests := []struct {
		path string
		name string
		ok   bool
	}{
		{"/debian/pool/main/c/curl/curl_7.88.1-10+deb12u5_amd64.deb", "curl", true},
		{"/debian/pool/main/liba/libapt-pkg-perl/libapt-pkg-perl_0.1.40_amd64.deb", "libapt-pkg-perl", true},
		{"/debian/pool/non-free/n/nvidia-driver/nvidia-driver_535.183.01-1_amd64.deb", "nvidia-driver", true},
		{"/ubuntu/pool/main/o/openssl/openssl_3.0.2-0ubuntu1_amd64.deb", "openssl", true},
		{"/debian/dists/bookworm/main/binary-amd64/Packages.gz", "", true},
		{"/debian/dists/bookworm/Release", "", true},
		{"/debian/dists/bookworm/InRelease", "", true},
	}
	for _, tt := range tests {
		name, ok := ParsePackageName(tt.path, "debian")
		if ok != tt.ok || name != tt.name {
			t.Errorf("ParsePackageName(%q, debian) = (%q, %v), want (%q, %v)",
				tt.path, name, ok, tt.name, tt.ok)
		}
	}
}

func TestParsePackageName_Go(t *testing.T) {
	tests := []struct {
		path string
		name string
		ok   bool
	}{
		{"/github.com/gorilla/mux/@v/v1.8.0.zip", "github.com/gorilla/mux", true},
		{"/github.com/gorilla/mux/@v/v1.8.0.info", "github.com/gorilla/mux", true},
		{"/github.com/gorilla/mux/@v/v1.8.0.mod", "github.com/gorilla/mux", true},
		{"/github.com/gorilla/mux/@latest", "github.com/gorilla/mux", true},
		{"/golang.org/x/net/@v/v0.17.0.zip", "golang.org/x/net", true},
		// Uppercase encoding: !g -> G
		{"/github.com/!azure/azure-sdk-for-go/@v/v1.0.0.zip", "github.com/Azure/azure-sdk-for-go", true},
		{"/", "", false},
	}
	for _, tt := range tests {
		name, ok := ParsePackageName(tt.path, "golang")
		if ok != tt.ok || name != tt.name {
			t.Errorf("ParsePackageName(%q, golang) = (%q, %v), want (%q, %v)",
				tt.path, name, ok, tt.name, tt.ok)
		}
	}
}

func TestParsePackageName_NPM(t *testing.T) {
	tests := []struct {
		path string
		name string
		ok   bool
	}{
		{"/express", "express", true},
		{"/express/4.18.2", "express", true},
		{"/@types/node", "@types/node", true},
		{"/@types/node/20.0.0", "@types/node", true},
		{"/@babel/core", "@babel/core", true},
		{"/@babel/core/-/core-7.23.2.tgz", "@babel/core", true},
		{"/@scope%2fpackage", "@scope/package", true},
		{"/", "", true},
	}
	for _, tt := range tests {
		name, ok := ParsePackageName(tt.path, "npm")
		if ok != tt.ok || name != tt.name {
			t.Errorf("ParsePackageName(%q, npm) = (%q, %v), want (%q, %v)",
				tt.path, name, ok, tt.name, tt.ok)
		}
	}
}

func TestParsePackageName_PyPI(t *testing.T) {
	tests := []struct {
		path string
		name string
		ok   bool
	}{
		{"/simple/requests/", "requests", true},
		{"/simple/requests", "requests", true},
		{"/simple/Flask/", "flask", true},           // normalized to lowercase
		{"/simple/my_package/", "my-package", true},  // underscores -> hyphens
		{"/pypi/requests/json", "requests", true},
		{"/pypi/requests/3.31.0/json", "requests", true},
		{"/simple/", "", true},                        // index page
		{"/packages/ab/cd/ef01/requests-2.31.0-py3-none-any.whl", "requests", true},
	}
	for _, tt := range tests {
		name, ok := ParsePackageName(tt.path, "pypi")
		if ok != tt.ok || name != tt.name {
			t.Errorf("ParsePackageName(%q, pypi) = (%q, %v), want (%q, %v)",
				tt.path, name, ok, tt.name, tt.ok)
		}
	}
}

func TestParsePackageName_NuGet(t *testing.T) {
	tests := []struct {
		path string
		name string
		ok   bool
	}{
		{"/v3-flatcontainer/newtonsoft.json/index.json", "newtonsoft.json", true},
		{"/v3-flatcontainer/Newtonsoft.Json/13.0.1/newtonsoft.json.13.0.1.nupkg", "newtonsoft.json", true},
		{"/v3-flatcontainer/microsoft.extensions.logging/index.json", "microsoft.extensions.logging", true},
		{"/v3/index.json", "", true}, // service index
	}
	for _, tt := range tests {
		name, ok := ParsePackageName(tt.path, "nuget")
		if ok != tt.ok || name != tt.name {
			t.Errorf("ParsePackageName(%q, nuget) = (%q, %v), want (%q, %v)",
				tt.path, name, ok, tt.name, tt.ok)
		}
	}
}

func TestCheckPackageApproval(t *testing.T) {
	mgr := approval.NewManager()

	// No approvals yet.
	if CheckPackageApproval(mgr, "curl") {
		t.Error("expected false with no approvals")
	}

	// Empty package name (metadata) should be auto-approved.
	if !CheckPackageApproval(mgr, "") {
		t.Error("expected true for empty package (metadata)")
	}

	// Approve the package.
	mgr.Decide("curl", "", "", "", approval.StatusApproved, "")
	if !CheckPackageApproval(mgr, "curl") {
		t.Error("expected true after approving package")
	}

	// Different package should not match.
	if CheckPackageApproval(mgr, "wget") {
		t.Error("expected false for different package")
	}
}

func TestMatchPackageRef(t *testing.T) {
	tests := []struct {
		pattern string
		pkg     string
		want    bool
	}{
		{"express", "express", true},
		{"express", "lodash", false},
		{"github.com/gorilla/*", "github.com/gorilla/mux", true},
		{"github.com/gorilla/*", "github.com/gorilla/handlers", true},
		{"github.com/gorilla/*", "github.com/gin-gonic/gin", false},
		{"@types/*", "@types/node", true},
		{"@types/*", "@types/react", true},
		{"@types/*", "@babel/core", false},
	}
	for _, tt := range tests {
		got := MatchPackageRef(tt.pattern, tt.pkg)
		if got != tt.want {
			t.Errorf("MatchPackageRef(%q, %q) = %v, want %v", tt.pattern, tt.pkg, got, tt.want)
		}
	}
}

func TestCheckPackageApproval_Wildcard(t *testing.T) {
	mgr := approval.NewManager()

	// Wildcard approval.
	mgr.Decide("github.com/gorilla/*", "", "", "", approval.StatusApproved, "")
	if !CheckPackageApproval(mgr, "github.com/gorilla/mux") {
		t.Error("expected true after wildcard approval")
	}
	if !CheckPackageApproval(mgr, "github.com/gorilla/handlers") {
		t.Error("expected true for another package under wildcard")
	}
	if CheckPackageApproval(mgr, "github.com/gin-gonic/gin") {
		t.Error("expected false for package not under wildcard")
	}
}

func TestParsePackageName_Alpine(t *testing.T) {
	tests := []struct {
		path string
		name string
		ok   bool
	}{
		{"/v3.19/main/x86_64/curl-8.5.0-r0.apk", "curl", true},
		{"/v3.19/community/x86_64/docker-24.0.7-r0.apk", "docker", true},
		{"/v3.19/main/x86_64/APKINDEX.tar.gz", "", true}, // metadata
		{"/v3.19/main/x86_64/", "", true},                 // index
	}
	for _, tt := range tests {
		name, ok := ParsePackageName(tt.path, "alpine")
		if ok != tt.ok || name != tt.name {
			t.Errorf("ParsePackageName(%q, alpine) = (%q, %v), want (%q, %v)",
				tt.path, name, ok, tt.name, tt.ok)
		}
	}
}

func TestParsePackageName_Ubuntu(t *testing.T) {
	tests := []struct {
		path string
		name string
		ok   bool
	}{
		{"/ubuntu/pool/main/o/openssl/openssl_3.0.2-0ubuntu1_amd64.deb", "openssl", true},
		{"/ubuntu/pool/universe/n/nginx/nginx_1.24.0-1_amd64.deb", "nginx", true},
		{"/ubuntu/dists/jammy/main/binary-amd64/Packages.gz", "", true}, // metadata
		{"/ubuntu/dists/jammy/InRelease", "", true},                     // metadata
	}
	for _, tt := range tests {
		name, ok := ParsePackageName(tt.path, "ubuntu")
		if ok != tt.ok || name != tt.name {
			t.Errorf("ParsePackageName(%q, ubuntu) = (%q, %v), want (%q, %v)",
				tt.path, name, ok, tt.name, tt.ok)
		}
	}
}

func TestParsePackageName_Rust(t *testing.T) {
	tests := []struct {
		path string
		name string
		ok   bool
	}{
		{"/api/v1/crates/serde", "serde", true},
		{"/api/v1/crates/serde/1.0.0/download", "serde", true},
		{"/api/v1/crates/tokio-core", "tokio-core", true},
		{"/", "", true}, // root
	}
	for _, tt := range tests {
		name, ok := ParsePackageName(tt.path, "rust")
		if ok != tt.ok || name != tt.name {
			t.Errorf("ParsePackageName(%q, rust) = (%q, %v), want (%q, %v)",
				tt.path, name, ok, tt.name, tt.ok)
		}
	}
}

func TestParsePackageName_PowerShell(t *testing.T) {
	tests := []struct {
		path string
		name string
		ok   bool
	}{
		{"/api/v2/package/Az/10.0.0", "Az", true},
		{"/api/v2/package/PSReadLine/2.3.4", "PSReadLine", true},
		{"/api/v2/package/Pester", "Pester", true},
		{"/api/v2/", "", true}, // index
	}
	for _, tt := range tests {
		name, ok := ParsePackageName(tt.path, "powershell")
		if ok != tt.ok || name != tt.name {
			t.Errorf("ParsePackageName(%q, powershell) = (%q, %v), want (%q, %v)",
				tt.path, name, ok, tt.name, tt.ok)
		}
	}
}

func TestParsePackageName_UnknownType(t *testing.T) {
	_, ok := ParsePackageName("/some/path", "unknown")
	if ok {
		t.Error("expected false for unregistered type")
	}
}

func TestTypeLabel(t *testing.T) {
	if got := TypeLabel("debian"); got != "Debian" {
		t.Errorf("TypeLabel(debian) = %q, want Debian", got)
	}
	if got := TypeLabel("golang"); got != "Go" {
		t.Errorf("TypeLabel(golang) = %q, want Go", got)
	}
	// Unknown type returns the raw string.
	if got := TypeLabel("custom"); got != "custom" {
		t.Errorf("TypeLabel(custom) = %q, want custom", got)
	}
}

func TestDecodeCaps(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"!azure", "Azure"},
		{"!g!hub", "GHub"},
		{"github.com/!azure/sdk", "github.com/Azure/sdk"},
	}
	for _, tt := range tests {
		got := decodeCaps(tt.input)
		if got != tt.want {
			t.Errorf("decodeCaps(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizePackageName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"requests", "requests"},
		{"Flask", "flask"},
		{"my_package", "my-package"},
		{"some.pkg", "some-pkg"},
		{"My_Package.Name", "my-package-name"},
	}
	for _, tt := range tests {
		got := normalizePackageName(tt.input)
		if got != tt.want {
			t.Errorf("normalizePackageName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
