// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package freebox

import (
	"context"
	"fmt"
)

// ListInterfaces returns the browsable LAN interfaces (typically "pub" and
// possibly "ipv6").
func (c *Client) ListInterfaces(ctx context.Context) ([]LanInterface, error) {
	var ifaces []LanInterface
	if err := c.doAuth(ctx, "GET", "lan/browser/interfaces/", nil, &ifaces); err != nil {
		return nil, err
	}
	return ifaces, nil
}

// ListHosts returns the hosts known by the Freebox on the given interface.
func (c *Client) ListHosts(ctx context.Context, iface string) ([]LanHost, error) {
	var hosts []LanHost
	if err := c.doAuth(ctx, "GET", fmt.Sprintf("lan/browser/%s/", iface), nil, &hosts); err != nil {
		return nil, err
	}
	return hosts, nil
}
