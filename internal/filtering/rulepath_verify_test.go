package filtering_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyRulePath verifies the rule effectiveness path described in
// filter-rule-matching.md.  It is a temporary verification test.
func TestVerifyRulePath(t *testing.T) {
	blockRules := "||blocked.example^\n" +
		"||multi.example^\n" +
		"||important.example^$important\n"

	conf := &filtering.Config{
		Logger:                testLogger,
		SafeBrowsingCacheSize: 10000,
		ParentalCacheSize:     10000,
		SafeSearchCacheSize:   1000,
		CacheTime:             30,
	}

	f, err := filtering.New(conf, []filtering.Filter{{
		ID:   1,
		Data: []byte(blockRules),
	}})
	require.NoError(t, err)

	setts := &filtering.Settings{
		FilteringEnabled:  true,
		ProtectionEnabled: true,
	}

	// 1. A plain blocking rule matches and filters the host.
	res, err := f.CheckHost("blocked.example", dns.TypeA, setts)
	require.NoError(t, err)
	assert.True(t, res.IsFiltered)
	assert.Equal(t, filtering.FilteredBlockList, res.Reason)
	require.Len(t, res.Rules, 1)
	assert.Equal(t, "||blocked.example^", res.Rules[0].Text)
	t.Logf("blocked.example -> reason=%s rule=%q", res.Reason, res.Rules[0].Text)

	// 2. An unknown host is not filtered.
	res, err = f.CheckHost("unknown.example", dns.TypeA, setts)
	require.NoError(t, err)
	assert.False(t, res.IsFiltered)
	assert.Equal(t, filtering.NotFilteredNotFound, res.Reason)

	// 3. $important blocking rule beats a @@ exception in the same engine.
	f3, err := filtering.New(conf, []filtering.Filter{{
		ID:   3,
		Data: []byte("||important.example^$important\n@@||important.example^\n"),
	}})
	require.NoError(t, err)

	res, err = f3.CheckHost("important.example", dns.TypeA, setts)
	require.NoError(t, err)
	assert.True(t, res.IsFiltered)
	assert.Equal(t, filtering.FilteredBlockList, res.Reason)
	t.Logf("important.example -> reason=%s rule=%q", res.Reason, res.Rules[0].Text)

	// 4. A @@ exception beats a plain blocking rule in the same engine.
	f4, err := filtering.New(conf, []filtering.Filter{{
		ID:   4,
		Data: []byte("||allowed.example^\n@@||allowed.example^\n"),
	}})
	require.NoError(t, err)

	res, err = f4.CheckHost("allowed.example", dns.TypeA, setts)
	require.NoError(t, err)
	assert.False(t, res.IsFiltered)
	assert.Equal(t, filtering.NotFilteredAllowList, res.Reason)
	t.Logf("allowed.example -> reason=%s rule=%q", res.Reason, res.Rules[0].Text)

	// 5. Hosts syntax: /etc/hosts-style rule rewrites to an IP.
	f5, err := filtering.New(conf, []filtering.Filter{{
		ID:   5,
		Data: []byte("192.0.2.1 hosts.example\n"),
	}})
	require.NoError(t, err)

	res, err = f5.CheckHost("hosts.example", dns.TypeA, setts)
	require.NoError(t, err)
	assert.True(t, res.IsFiltered)
	assert.Equal(t, filtering.FilteredBlockList, res.Reason)
	require.Len(t, res.Rules, 1)
	assert.Equal(t, "192.0.2.1", res.Rules[0].IP.String())
	t.Logf("hosts.example -> reason=%s ip=%s", res.Reason, res.Rules[0].IP)
}

// TestVerifyCustomUserRule verifies that a custom user rule from the
// configuration (list ID 0) blocks the host.
func TestVerifyCustomUserRule(t *testing.T) {
	conf := &filtering.Config{
		Logger:                testLogger,
		SafeBrowsingCacheSize: 10000,
		ParentalCacheSize:     10000,
		SafeSearchCacheSize:   1000,
		CacheTime:             30,
		UserRules:             []string{"||blocked-by-custom.example^"},
	}

	f, err := filtering.New(conf, nil)
	require.NoError(t, err)

	f.EnableFilters(false)

	setts := &filtering.Settings{
		FilteringEnabled:  true,
		ProtectionEnabled: true,
	}

	res, err := f.CheckHost("blocked-by-custom.example", dns.TypeA, setts)
	require.NoError(t, err)
	assert.True(t, res.IsFiltered)
	assert.Equal(t, filtering.FilteredBlockList, res.Reason)
	require.Len(t, res.Rules, 1)
	assert.Equal(t, int64(0), int64(res.Rules[0].FilterListID))
	t.Logf("blocked-by-custom.example -> reason=%s list=%d rule=%q",
		res.Reason, res.Rules[0].FilterListID, res.Rules[0].Text)
}
