//go:build !windows || !amd64

package divert

import "context"

func (*Proxy) run(context.Context) error { return ErrUnsupportedPlatform }
