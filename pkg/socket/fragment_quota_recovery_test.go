package socket

import (
	"errors"
	"testing"
	"time"
)

// Inspect both accounting and admission: a zero aggregate balance alone cannot
// prove the per-source admission slots became usable again.
func TestIPv4FragmentSourceQuotaRecoversAfterExpiry(t *testing.T) {
	budget := &resourceBudget{limit: 2 * ipv4FragmentSources * ipv4FragmentCharge}
	r := newIPv4Fragments(budget, budget.limit)
	t.Cleanup(r.close)
	now := time.Unix(1, 0)
	for id := 0; id < ipv4FragmentSources; id++ {
		if _, _, err := r.add(fragmentFixture(17, uint16(id), 0, true, make([]byte, 8)), now); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := r.add(fragmentFixture(17, 100, 0, true, make([]byte, 8)), now); !errors.Is(err, ErrIPv4FragmentLimit) {
		t.Fatal("source saturation not enforced", err)
	}
	// Expiry transfers ownership; capacity must stay reserved until delivery
	// owners release the detached assemblies.
	expired := r.expire(now.Add(ipv4FragmentLifetime))
	if len(expired) != ipv4FragmentSources {
		t.Fatal("expiry count mismatch", len(expired))
	}
	assertBudget(t, budget, uint64(ipv4FragmentSources*ipv4FragmentCharge))
	for _, d := range expired {
		r.release(d)
	}
	assertBudget(t, budget, 0)
	if r.snapshot()["live"] != 0 || r.snapshot()["reserved_bytes"] != 0 {
		t.Fatal("expiry retained global quota")
	}
	for id := 0; id < ipv4FragmentSources; id++ {
		if _, _, err := r.add(fragmentFixture(17, uint16(id+200), 0, true, make([]byte, 8)), now.Add(ipv4FragmentLifetime)); err != nil {
			t.Fatal("source quota did not recover after expiry", err)
		}
	}
	r.close()
	assertBudget(t, budget, 0)
}
