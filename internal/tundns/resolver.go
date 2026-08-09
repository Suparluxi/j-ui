package tundns

import (
	"context"
	"net"
	"sync/atomic"
	"time"
)

var publicResolvers = [...]string{
	"1.1.1.1:53",
	"8.8.8.8:53",
}

func IPv4Dialer() *net.Dialer {
	var next atomic.Uint32
	resolver := &net.Resolver{
		PreferGo:     true,
		StrictErrors: false,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			server := publicResolvers[next.Add(1)%uint32(len(publicResolvers))]
			dialer := &net.Dialer{Timeout: 5 * time.Second}
			if network == "tcp" || network == "tcp4" {
				return dialer.DialContext(ctx, "tcp4", server)
			}
			return dialer.DialContext(ctx, "udp4", server)
		},
	}
	return &net.Dialer{Timeout: 15 * time.Second, Resolver: resolver}
}
