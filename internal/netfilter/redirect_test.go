package netfilter

import (
	"errors"
	"strings"
	"testing"
)

// fakeIPTables records the invocations and answers -C checks from the set of
// rules it considers installed.
type fakeIPTables struct {
	calls     []string
	installed map[string]bool
	failAdd   map[string]bool
}

func newFakeIPTables() *fakeIPTables {
	return &fakeIPTables{installed: map[string]bool{}, failAdd: map[string]bool{}}
}

func (f *fakeIPTables) run(args ...string) error {
	line := strings.Join(args, " ")
	f.calls = append(f.calls, line)

	rule := strings.Join(args[4:], " ") // the spec after "-t nat -C/-A PREROUTING"
	switch args[2] {
	case "-C":
		if f.installed[rule] {
			return nil
		}
		return errors.New("exit status 1")
	case "-A":
		if f.failAdd[rule] {
			return errors.New("iptables: no chain/target/match by that name")
		}
		f.installed[rule] = true
		return nil
	}
	return errors.New("unexpected command: " + line)
}

func testRedirector(f *fakeIPTables) *Redirector {
	return &Redirector{Interface: "eth1", ExcludeIP: "10.255.255.1", ToPort: 8443, Run: f.run}
}

func TestRedirectSpec(t *testing.T) {
	r := testRedirector(newFakeIPTables())
	got := strings.Join(r.redirectSpec(6443), " ")
	want := "-i eth1 -p tcp --dport 6443 ! -d 10.255.255.1 -j REDIRECT --to-port 8443"
	if got != want {
		t.Errorf("redirectSpec = %q, want %q", got, want)
	}
}

func TestRedirectSpec_NoExcludeIP(t *testing.T) {
	r := &Redirector{Interface: "eth1", ToPort: 8443}
	got := strings.Join(r.redirectSpec(443), " ")
	want := "-i eth1 -p tcp --dport 443 -j REDIRECT --to-port 8443"
	if got != want {
		t.Errorf("redirectSpec = %q, want %q", got, want)
	}
}

func TestEnsure_AddsMissingRule(t *testing.T) {
	f := newFakeIPTables()
	added, err := testRedirector(f).Ensure(6443)
	if err != nil {
		t.Fatalf("Ensure() error: %v", err)
	}
	if !added {
		t.Error("expected the rule to be reported as added")
	}
	if len(f.calls) != 2 {
		t.Fatalf("expected a check and an append, got %v", f.calls)
	}
	if !strings.Contains(f.calls[1], "-A PREROUTING") || !strings.Contains(f.calls[1], "--dport 6443") {
		t.Errorf("unexpected append call: %q", f.calls[1])
	}
}

func TestEnsure_SkipsExistingRule(t *testing.T) {
	f := newFakeIPTables()
	r := testRedirector(f)
	f.installed[strings.Join(r.redirectSpec(443), " ")] = true

	added, err := r.Ensure(443)
	if err != nil {
		t.Fatalf("Ensure() error: %v", err)
	}
	if added {
		t.Error("an existing rule must not be added again")
	}
	if len(f.calls) != 1 {
		t.Errorf("expected only the check call, got %v", f.calls)
	}
}

func TestEnsure_Idempotent(t *testing.T) {
	f := newFakeIPTables()
	r := testRedirector(f)
	if _, err := r.Ensure(6443); err != nil {
		t.Fatalf("first Ensure() error: %v", err)
	}
	added, err := r.Ensure(6443)
	if err != nil {
		t.Fatalf("second Ensure() error: %v", err)
	}
	if added {
		t.Error("second Ensure() must not add a duplicate rule")
	}
}

func TestEnsureAll_ContinuesAfterFailure(t *testing.T) {
	f := newFakeIPTables()
	r := testRedirector(f)
	f.failAdd[strings.Join(r.redirectSpec(8443), " ")] = true

	added, errs := r.EnsureAll([]int{443, 8443, 6443})
	if len(errs) != 1 {
		t.Fatalf("expected exactly one error, got %v", errs)
	}
	if !strings.Contains(errs[0].Error(), "tcp/8443") {
		t.Errorf("error should name the failing port: %v", errs[0])
	}
	if len(added) != 2 || added[0] != 443 || added[1] != 6443 {
		t.Errorf("expected 443 and 6443 to be added, got %v", added)
	}
}
