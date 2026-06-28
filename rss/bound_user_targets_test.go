package rss

import "testing"

// TestBoundAdmitsOwnerTargets pins ValidateCommittee = norm AND partition-availability.
// A committee is admissible only if it can actually SIGN: norm-viable (τ·C·η < γ2)
// AND its reconstruction partition exists (the T==N base case, or a canonicalSharing
// entry — Algorithm 6, table-limited to N≤6 until the general partition lands).
// HONEST state: the owner's n-of-n families (n=8,t=8; n=16,t=16) sign now; the
// fault-tolerant T<N families (n=8,t=7 default; n=16,t=14) are norm-viable but await
// the general Algorithm-6 partition. See lux_pulsar_sampled_cert.
func TestBoundAdmitsOwnerTargets(t *testing.T) {
	for _, c := range []struct {
		n, tt int
		admit bool
		why   string
	}{
		{8, 8, true, "T==N base-case partition"},
		{16, 16, true, "T==N base-case partition"},
		{6, 4, true, "N≤6 in canonicalSharing table"},
		{8, 7, false, "norm-viable but no partition (awaits general Algorithm 6)"},
		{16, 14, false, "norm-viable but no partition"},
		{16, 12, false, "norm blown (τCη > γ2)"},
		{64, 5, false, "norm blown"},
	} {
		got := ValidateCommittee(c.tt, c.n) == nil
		if got != c.admit {
			t.Errorf("n=%d t=%d: admit=%v want %v (%s)", c.n, c.tt, got, c.admit, c.why)
		}
	}
}
