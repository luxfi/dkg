package rss

import "testing"

// TestBoundAdmitsOwnerTargets pins the per-(N,T) norm-viability bound against the
// owner's sampled-committee param families: n=8,t=7 (default) + n=8,t=8 + n=16,t=14
// are admitted (τ·C(N,N−T+1)·η < γ2); n=16,t=12 + n=64,t=5 are rejected (norm blows
// the FIPS-204 hint budget). See lux_pulsar_sampled_cert.
func TestBoundAdmitsOwnerTargets(t *testing.T) {
	for _, c := range []struct {
		n, tt int
		admit bool
	}{{8, 7, true}, {8, 8, true}, {16, 14, true}, {16, 12, false}, {64, 5, false}} {
		got := ValidateCommittee(c.tt, c.n) == nil
		if got != c.admit {
			t.Errorf("n=%d t=%d: admit=%v want %v", c.n, c.tt, got, c.admit)
		}
	}
}
