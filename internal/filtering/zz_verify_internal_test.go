package filtering

import (
	"context"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering/rulelist"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyRuleEffectivePath verifies the full path of a filtering rule:
// list data -> rule storage -> DNS engine -> CheckHost result.
func TestVerifyRuleEffectivePath(t *testing.T) {
	blockData := "||ads.example.com^\n||multi.example.com^\n|multi.example.com^$important\n"

	t.Run("block rule matches", func(t *testing.T) {
		d, setts := newForTest(t, nil, []Filter{{
			ID:   1,
			Data: []byte(blockData),
		}})

		res, err := d.CheckHost("ads.example.com", dns.TypeA, setts)
		require.NoError(t, err)
		assert.True(t, res.IsFiltered)
		assert.Equal(t, FilteredBlockList, res.Reason)
		require.Len(t, res.Rules, 1)
		assert.Equal(t, "||ads.example.com^", res.Rules[0].Text)
		assert.Equal(t, rulelist.APIID(1), res.Rules[0].FilterListID)
	})

	t.Run("multiple rules hit, important wins", func(t *testing.T) {
		d, setts := newForTest(t, nil, []Filter{{
			ID:   1,
			Data: []byte(blockData),
		}})

		res, err := d.CheckHost("multi.example.com", dns.TypeA, setts)
		require.NoError(t, err)
		assert.True(t, res.IsFiltered)
		require.Len(t, res.Rules, 1)
		assert.Equal(t, "|multi.example.com^$important", res.Rules[0].Text)
	})

	t.Run("custom whitelist rule beats block rule in same engine", func(t *testing.T) {
		d, setts := newForTest(t, nil, []Filter{
			{ID: rulelist.IDCustom, Data: []byte("@@||ads.example.com^")},
			{ID: 1, Data: []byte(blockData)},
		})

		res, err := d.CheckHost("ads.example.com", dns.TypeA, setts)
		require.NoError(t, err)
		assert.False(t, res.IsFiltered)
		assert.Equal(t, NotFilteredAllowList, res.Reason)
		require.Len(t, res.Rules, 1)
		assert.Equal(t, "@@||ads.example.com^", res.Rules[0].Text)
	})

	t.Run("allowlist engine short-circuits block engine", func(t *testing.T) {
		d, setts := newForTest(t, nil, nil)

		err := d.initFiltering(
			context.Background(),
			[]Filter{{ID: 2, Data: []byte("||ads.example.com^")}},
			[]Filter{{ID: 1, Data: []byte(blockData)}},
		)
		require.NoError(t, err)

		res, err := d.CheckHost("ads.example.com", dns.TypeA, setts)
		require.NoError(t, err)
		assert.False(t, res.IsFiltered)
		assert.Equal(t, NotFilteredAllowList, res.Reason)
		require.Len(t, res.Rules, 1)
		assert.Equal(t, rulelist.APIID(2), res.Rules[0].FilterListID)
	})

	t.Run("protection disabled ignores block match", func(t *testing.T) {
		d, setts := newForTest(t, nil, []Filter{{
			ID:   1,
			Data: []byte(blockData),
		}})
		setts.ProtectionEnabled = false

		res, err := d.CheckHost("ads.example.com", dns.TypeA, setts)
		require.NoError(t, err)
		assert.False(t, res.IsFiltered)
		assert.Equal(t, NotFilteredNotFound, res.Reason)
	})
}
