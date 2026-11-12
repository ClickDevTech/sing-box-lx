//go:build with_utls

package tls

// lx:begin SPEC 122 release the uTLS handshake state
//
// After a uTLS/REALITY handshake the UConn keeps the ClientHello, the key share
// private keys (an ML-KEM-768 decapsulation key is 7.8 KiB) and the extension
// objects for the life of the connection; the library never reads them again
// on TLS 1.3. releaseHandshakeState drops them once the handshake succeeded:
// ~14 KiB per connection in the core, ~3 KiB more through the utls fork's
// ReleaseHandshakeState (clientHelloSpec, ECH context).
//
// The upstream ALPN wrapper rebuilt the ClientHello on every HandshakeContext
// call to override the preset's ALPN; after a release a second call would
// rebuild from nil fields and panic. lxUTLSConn overrides the ALPN once, in the
// first HandshakeContext (the same moment and sequence as upstream, so the wire
// is unchanged and the build stays outside ECHClientConfig's lock), and a later
// call goes straight to the UConn fast path. The upstream wrapper gets an empty
// protocol list and never rebuilds.
//
// Not covered: an implicit handshake from UConn.Read/Write bypasses the wrapper
// (no ALPN override, as upstream, and no release); nothing in the tree relies on it.

import (
	"context"
	"sync"

	utls "github.com/metacubex/utls"
)

type lxUTLSConn struct {
	utlsALPNWrapper
	nextProtos    []string
	keyShare      string // SPEC 156 — C.RealityKeyShare*
	helloPrepared bool
	access        sync.Mutex
}

func newLXUTLSConn(uConn *utls.UConn, nextProtos []string) *lxUTLSConn {
	return &lxUTLSConn{
		utlsALPNWrapper: utlsALPNWrapper{utlsConnWrapper: utlsConnWrapper{uConn}},
		nextProtos:      nextProtos,
	}
}

// withKeyShare sets the SPEC 156 `utls.key_share` policy, applied with the ALPN
// override in the first HandshakeContext.
func (c *lxUTLSConn) withKeyShare(keyShare string) *lxUTLSConn {
	c.keyShare = keyShare
	return c
}

func (c *lxUTLSConn) HandshakeContext(ctx context.Context) error {
	c.access.Lock()
	defer c.access.Unlock()
	if !c.helloPrepared && (len(c.nextProtos) > 0 || c.keyShare != "") {
		// A failed build leaves the flag unset: a retry rebuilds, as upstream.
		err := lxPrepareHello(c.UConn, c.nextProtos, c.keyShare)
		if err != nil {
			return err
		}
		c.helloPrepared = true
	}
	err := c.UConn.HandshakeContext(ctx)
	if err != nil {
		// The state stays for the REALITY-style fallback and for the cached
		// handshake error a retry returns.
		return err
	}
	releaseHandshakeState(c.UConn)
	return nil
}

// lxPrepareHello builds the ClientHello once: the ALPN override (SPEC 122), then
// the key_share policy (SPEC 156). Without a policy the wire is what upstream sends.
func lxPrepareHello(uConn *utls.UConn, nextProtos []string, keyShare string) error {
	var err error
	if len(nextProtos) > 0 {
		err = lxApplyALPN(uConn, nextProtos)
	} else {
		err = uConn.BuildHandshakeState()
	}
	if err != nil || keyShare == "" {
		return err
	}
	return lxApplyKeyShare(uConn, keyShare)
}

// lxApplyALPN builds the ClientHello and replaces the preset's ALPN list
// (utls ignores Config.NextProtos for presets). Upstream utlsALPNWrapper logic.
func lxApplyALPN(uConn *utls.UConn, nextProtos []string) error {
	err := uConn.BuildHandshakeState()
	if err != nil {
		return err
	}
	for _, extension := range uConn.Extensions {
		if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
			alpnExtension.AlpnProtocols = nextProtos
			return uConn.BuildHandshakeState()
		}
	}
	return nil
}

// releaseHandshakeState drops the handshake state of a completed TLS 1.3
// connection. TLS 1.2 keeps it: browser presets enable renegotiation through
// renegotiation_info (utls sets Config.Renegotiation from the extension), and a
// renegotiation rebuilds the hello from it; TLS 1.3 has no renegotiation.
// The fork method re-checks the version itself. Idempotent.
func releaseHandshakeState(uConn *utls.UConn) {
	if uConn.ConnectionState().Version != utls.VersionTLS13 {
		return
	}
	uConn.HandshakeState.Hello = nil
	uConn.HandshakeState.ServerHello = nil
	uConn.HandshakeState.State13 = utls.TLS13OnlyState{}
	uConn.Extensions = nil
	// The fork method also drops the ClientHelloSpec and ECH context; without
	// the fork (metacubex/utls) the core part above still applies.
	if releaser, isReleaser := any(uConn).(interface{ ReleaseHandshakeState() }); isReleaser {
		releaser.ReleaseHandshakeState()
	}
}

// lx:end SPEC 122
