package rss

import "testing"

// TestBoundAdmitsOwnerTargets pins the per-(N,T) NORM-viability gate against the
// owner's sampled-committee families: n=8,t=7 (default), n=8,t=8, n=16,t=14 are
// NORM-viable (τ·C(N,N−T+1)·η < γ2); n=16,t=12 + n=64,t=5 are norm-blown.
// NOTE: ValidateCommittee is the NORM gate. SIGNING the fault-tolerant T<N families
// at N>6 (n=8,t=7; n=16,t=14) additionally needs the general Algorithm-6 partition
// (canonicalSharing is table-limited to N≤6); until then Sign fails CLOSED with "no
// balanced partition". The T==N families (n=8,t=8; n=16,t=16) sign now. See
// lux_pulsar_sampled_cert.
func TestBoundAdmitsOwnerTargets(t *testing.T) {
	for _, c := range []struct {
		n, tt   int
		normOK  bool
	}{{8, 7, true}, {8, 8, true}, {16, 14, true}, {16, 12, false}, {64, 5, false}} {
		got := ValidateCommittee(c.tt, c.n) == nil
		if got != c.normOK {
			t.Errorf("n=%d t=%d: norm-admit=%v want %v", c.n, c.tt, got, c.normOK)
		}
	}
}
