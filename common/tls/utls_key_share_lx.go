//go:build with_utls

package tls

// lx:begin SPEC 156 utls key_share
//
// `tls.utls.key_share` is the plain-TLS twin of `tls.reality.key_share` (SPEC
// 089): "" sends what the fingerprint carries, "classical" strips
// X25519MLKEM768 from supported_groups and key_share, "hybrid" fails the
// handshake when the fingerprint has no hybrid share. Unlike REALITY, a plain TLS
// server (Xray TLS inbound, Caddy, nginx, a CDN) accepts the classical hello, so
// here the option is a working answer for networks that lose a ClientHello split
// over two TCP segments, not a trade against the server.
//
// The strip runs on a built handshake state and is followed by a rebuild: the
// preset is applied once, the second build only re-marshals the hello from the
// filtered extensions, and the X25519 private key stays in KeyShareKeys.Ecdhe.
// Both lists are filtered on purpose: a hybrid group left in supported_groups
// would let a Go 1.24+ server answer with a HelloRetryRequest for it and get the
// long hello anyway.

import (
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"

	utls "github.com/metacubex/utls"
)

// lxUTLSKeyShare validates `tls.utls.key_share` when the outbound is built.
func lxUTLSKeyShare(options option.OutboundTLSOptions) (string, error) {
	if options.UTLS == nil {
		return C.RealityKeyShareDefault, nil
	}
	keyShare := options.UTLS.KeyShare
	switch keyShare {
	case C.RealityKeyShareDefault:
		return keyShare, nil
	case C.RealityKeyShareHybrid, C.RealityKeyShareClassical:
	default:
		return "", E.New("unknown utls key_share: ", keyShare, " (expected \"hybrid\" or \"classical\")")
	}
	if options.Reality != nil && options.Reality.Enabled {
		// The REALITY client builds its own UConn; one knob per handshake.
		return "", E.New("utls key_share is unsupported in reality, use reality.key_share")
	}
	if keyShare == C.RealityKeyShareClassical && options.ECH != nil && options.ECH.Enabled {
		// The ECH inner and outer hellos are assembled inside utls from the same
		// extensions; stripping them there is not covered.
		return "", E.New("utls key_share \"classical\" is unsupported with ECH")
	}
	return keyShare, nil
}

// lxApplyKeyShare applies the policy to a UConn whose handshake state is built.
func lxApplyKeyShare(uConn *utls.UConn, keyShare string) error {
	switch keyShare {
	case C.RealityKeyShareClassical:
		lxStripHybridKeyShare(uConn)
		return uConn.BuildHandshakeState()
	case C.RealityKeyShareHybrid:
		if !realityHelloCarriesHybridShare(uConn) {
			return E.New("utls key_share \"hybrid\": fingerprint ", uConn.ClientHelloID.Client, " ", uConn.ClientHelloID.Version, " carries no X25519MLKEM768 key share")
		}
	}
	return nil
}

// lxStripHybridKeyShare removes X25519MLKEM768 from supported_groups and
// key_share. The caller rebuilds the handshake state.
func lxStripHybridKeyShare(uConn *utls.UConn) {
	for _, extension := range uConn.Extensions {
		if curves, isCurves := extension.(*utls.SupportedCurvesExtension); isCurves {
			curves.Curves = common.Filter(curves.Curves, func(curveID utls.CurveID) bool {
				return curveID != utls.X25519MLKEM768
			})
		}
		if keyShares, isKeyShares := extension.(*utls.KeyShareExtension); isKeyShares {
			keyShares.KeyShares = common.Filter(keyShares.KeyShares, func(share utls.KeyShare) bool {
				return share.Group != utls.X25519MLKEM768
			})
		}
	}
}

// lx:end SPEC 156
