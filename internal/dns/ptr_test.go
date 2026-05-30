// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package dns

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddrFromPTR(t *testing.T) {
	tests := []struct {
		name    string
		qname   string
		want    string
		wantErr bool
	}{
		{
			name:  "ipv4 simple",
			qname: "42.1.168.192.in-addr.arpa.",
			want:  "192.168.1.42",
		},
		{
			name:  "ipv4 boundary",
			qname: "1.1.168.192.in-addr.arpa.",
			want:  "192.168.1.1",
		},
		{
			name:  "ipv4 without trailing dot",
			qname: "42.1.168.192.in-addr.arpa",
			want:  "192.168.1.42",
		},
		{
			name:  "ipv4 mixed case",
			qname: "42.1.168.192.IN-ADDR.ARPA.",
			want:  "192.168.1.42",
		},
		{
			name:  "ipv6 full",
			qname: "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
			want:  "2001:db8::2",
		},
		{
			name:  "ipv6 link-local",
			qname: "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.",
			want:  "fe80::1",
		},
		{
			name:    "ipv4 too few labels",
			qname:   "168.192.in-addr.arpa.",
			wantErr: true,
		},
		{
			name:    "ipv4 too many labels",
			qname:   "5.42.1.168.192.in-addr.arpa.",
			wantErr: true,
		},
		{
			name:    "ipv4 non-numeric label",
			qname:   "x.1.168.192.in-addr.arpa.",
			wantErr: true,
		},
		{
			name:    "ipv4 octet out of range",
			qname:   "256.1.168.192.in-addr.arpa.",
			wantErr: true,
		},
		{
			name:    "ipv6 wrong nibble count",
			qname:   "1.0.0.2.ip6.arpa.",
			wantErr: true,
		},
		{
			name:    "ipv6 non-hex nibble",
			qname:   "z.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.",
			wantErr: true,
		},
		{
			name:    "not arpa",
			qname:   "example.com.",
			wantErr: true,
		},
		{
			name:    "empty",
			qname:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AddrFromPTR(tt.qname)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				want := netip.MustParseAddr(tt.want)
				assert.Equal(t, want, got)
			}
		})
	}
}
