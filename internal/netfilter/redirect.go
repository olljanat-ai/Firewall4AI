// Package netfilter programs the iptables REDIRECT rules that hand agent
// traffic to the transparent listeners.
//
// The boot-time script installs the baseline rules (HTTP on 80, HTTPS on 443).
// Everything else is driven from the application config, because HTTPS is not
// always served on 443: Kubernetes API servers are typically published on 6443
// (kubeadm, Oracle OKE, Rancher) or 8443 (OpenShift, minikube). A port that is
// not redirected never reaches the proxy — the FORWARD chain rejects it and
// the agent sees "connection refused" with nothing in the request log — so the
// rules are (re)applied at startup for every configured port.
package netfilter

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// Redirector installs REDIRECT rules that send TCP traffic arriving on the
// agent interface to a local listener.
type Redirector struct {
	// Interface is the agent-facing interface the rules match on (eth1).
	Interface string
	// ExcludeIP is the proxy's own address on that interface; traffic
	// addressed to it directly is left alone.
	ExcludeIP string
	// ToPort is the local listener the traffic is redirected to.
	ToPort int
	// Run executes an iptables invocation. Defaults to the iptables binary;
	// tests replace it.
	Run func(args ...string) error
}

// redirectSpec builds the rule specification (everything after the chain name)
// for redirecting the given destination port to the local listener.
func (r *Redirector) redirectSpec(port int) []string {
	spec := []string{"-i", r.Interface, "-p", "tcp", "--dport", strconv.Itoa(port)}
	if r.ExcludeIP != "" {
		spec = append(spec, "!", "-d", r.ExcludeIP)
	}
	return append(spec, "-j", "REDIRECT", "--to-port", strconv.Itoa(r.ToPort))
}

// Ensure installs the REDIRECT rule for port unless it is already present.
// It reports whether a rule was added, so callers can log only real changes.
func (r *Redirector) Ensure(port int) (added bool, err error) {
	spec := r.redirectSpec(port)
	if err := r.run(append([]string{"-t", "nat", "-C", "PREROUTING"}, spec...)...); err == nil {
		return false, nil // already installed by the boot script or a previous run
	}
	if err := r.run(append([]string{"-t", "nat", "-A", "PREROUTING"}, spec...)...); err != nil {
		return false, fmt.Errorf("redirect tcp/%d to :%d: %w", port, r.ToPort, err)
	}
	return true, nil
}

// EnsureAll installs the REDIRECT rules for every port, returning the ports
// that were newly added and the errors for those that could not be installed.
// One failing port does not stop the others: a box where a single rule is
// rejected should still get the rest of its redirects.
func (r *Redirector) EnsureAll(ports []int) (added []int, errs []error) {
	for _, port := range ports {
		wasAdded, err := r.Ensure(port)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if wasAdded {
			added = append(added, port)
		}
	}
	return added, errs
}

func (r *Redirector) run(args ...string) error {
	if r.Run != nil {
		return r.Run(args...)
	}
	return runIPTables(args...)
}

// runIPTables executes iptables and returns its stderr as part of the error,
// which is where it explains why a rule was rejected.
func runIPTables(args ...string) error {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err == nil {
		return nil
	}
	if msg := strings.TrimSpace(string(out)); msg != "" {
		return fmt.Errorf("iptables %s: %w: %s", strings.Join(args, " "), err, msg)
	}
	return fmt.Errorf("iptables %s: %w", strings.Join(args, " "), err)
}
