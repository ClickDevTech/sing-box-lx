//go:build with_utls

package tls

// lx:begin SPEC 156 tests
//
// `tls.utls.key_share` on the plain uTLS client: "" keeps the fingerprint's
// hello, "classical" strips X25519MLKEM768 from both lists and still completes a
// handshake with a stock crypto/tls server (which picks X25519 without a
// HelloRetryRequest), "hybrid" fails early on a fingerprint without the share.
// The handshakes go through NewClient and ClientHandshake, the path every TCP
// transport (raw TCP, WebSocket, HTTPUpgrade, gRPC, HTTP, XHTTP h1/h2) takes.

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

var lxKeyShareFingerprints = []string{"chrome", "chrome_155", "firefox", "safari", "random", "randomized"}

func lxKeyShareOptions(fingerprint, keyShare string, alpn ...string) option.OutboundTLSOptions {
	return option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.com",
		Insecure:   true,
		ALPN:       alpn,
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint, KeyShare: keyShare},
	}
}

func lxNewKeyShareClient(t *testing.T, options option.OutboundTLSOptions) *UTLSClientConfig {
	t.Helper()
	config, err := NewClient(context.Background(), logger.NOP(), "example.com", options)
	require.NoError(t, err)
	client, isUTLS := config.(*UTLSClientConfig)
	require.True(t, isUTLS, "expected *UTLSClientConfig, got %T", config)
	return client
}

// lxKeyShareHello runs the handshake against a peer that hangs up after the
// first flight and returns the ClientHello that was built (a failed handshake
// keeps the state, SPEC 122).
func lxKeyShareHello(t *testing.T, client *UTLSClientConfig) *utls.UConn {
	t.Helper()
	conn, peer := net.Pipe()
	t.Cleanup(func() {
		conn.Close()
		peer.Close()
	})
	go func() {
		buffer := make([]byte, 64*1024)
		_, _ = peer.Read(buffer)
		peer.Close()
	}()
	tlsConn, err := client.Client(conn)
	require.NoError(t, err)
	uConn := tlsConn.(*lxUTLSConn)
	require.Error(t, uConn.HandshakeContext(context.Background()))
	require.NotNil(t, uConn.HandshakeState.Hello, "the hello must have been built")
	return uConn.UConn
}

func TestLxUTLSKeyShareDefaultKeepsHybrid(t *testing.T) {
	t.Parallel()
	for _, fingerprint := range lxKeyShareFingerprints {
		t.Run(fingerprint, func(t *testing.T) {
			t.Parallel()
			hello := lxKeyShareHello(t, lxNewKeyShareClient(t, lxKeyShareOptions(fingerprint, C.RealityKeyShareDefault, "h2"))).HandshakeState.Hello
			hybridIndex, hybridCount := lxIndexOfShare(hello.KeyShares, utls.X25519MLKEM768)
			require.NotEqual(t, -1, hybridIndex, "hybrid share missing from the wire hello")
			require.Equal(t, 1, hybridCount)
			require.NotEqual(t, -1, lxIndexOfCurve(hello.SupportedCurves, utls.X25519MLKEM768))
			require.GreaterOrEqual(t, len(hello.Raw), 1184+32, "hybrid hello must carry the ML-KEM share")
		})
	}
}

func TestLxUTLSKeyShareClassicalStripsHybrid(t *testing.T) {
	t.Parallel()
	for _, fingerprint := range lxKeyShareFingerprints {
		for _, alpn := range [][]string{{"h2"}, nil} {
			t.Run(fingerprint+"/alpn="+lxJoin(alpn), func(t *testing.T) {
				t.Parallel()
				uConn := lxKeyShareHello(t, lxNewKeyShareClient(t, lxKeyShareOptions(fingerprint, C.RealityKeyShareClassical, alpn...)))
				hello := uConn.HandshakeState.Hello

				hybridIndex, _ := lxIndexOfShare(hello.KeyShares, utls.X25519MLKEM768)
				require.Equal(t, -1, hybridIndex, "X25519MLKEM768 must be gone from key_share")
				require.Equal(t, -1, lxIndexOfCurve(hello.SupportedCurves, utls.X25519MLKEM768), "X25519MLKEM768 must be gone from supported_groups")
				classicalIndex, classicalCount := lxIndexOfShare(hello.KeyShares, utls.X25519)
				require.NotEqual(t, -1, classicalIndex, "X25519 share must stay")
				require.Equal(t, 1, classicalCount)
				require.Len(t, hello.KeyShares[classicalIndex].Data, 32)
				require.NotEqual(t, -1, lxIndexOfCurve(hello.SupportedCurves, utls.X25519))
				require.Less(t, len(hello.Raw), 1184, "classical hello must be shorter than an ML-KEM-768 encapsulation key alone (%d bytes)", len(hello.Raw))

				keys := uConn.HandshakeState.State13.KeyShareKeys
				require.NotNil(t, keys)
				require.NotNil(t, keys.Ecdhe)
				require.Equal(t, hello.KeyShares[classicalIndex].Data, keys.Ecdhe.PublicKey().Bytes())
				if len(alpn) > 0 {
					require.Equal(t, alpn, hello.AlpnProtocols, "the ALPN override must survive the rebuild")
				}
			})
		}
	}
}

func lxJoin(values []string) string {
	if len(values) == 0 {
		return "preset"
	}
	return values[0]
}

// lxKeyShareServer runs a stock crypto/tls server (default curve preferences,
// X25519MLKEM768 first) and reports what it saw and what it picked.
type lxKeyShareServerResult struct {
	offeredGroups []stdtls.CurveID
	curve         stdtls.CurveID
	err           error
}

func lxKeyShareServe(t *testing.T, conn net.Conn) <-chan lxKeyShareServerResult {
	result := make(chan lxKeyShareServerResult, 1)
	go func() {
		var offered []stdtls.CurveID
		server := stdtls.Server(conn, &stdtls.Config{
			Certificates: []stdtls.Certificate{lxReleaseCert(t, "example.com")},
			NextProtos:   []string{"h2", "http/1.1"},
			GetConfigForClient: func(hello *stdtls.ClientHelloInfo) (*stdtls.Config, error) {
				offered = hello.SupportedCurves
				return nil, nil
			},
		})
		defer server.Close()
		err := server.Handshake()
		result <- lxKeyShareServerResult{offered, server.ConnectionState().CurveID, err}
		if err == nil {
			buf := make([]byte, 4)
			n, _ := server.Read(buf)
			_, _ = server.Write(buf[:n])
		}
	}()
	return result
}

// End to end through the dispatcher: the classical hello completes a handshake
// with a default crypto/tls server, which settles on X25519; the default hello
// against the same server settles on the hybrid group, so the server would have
// taken ML-KEM had it been offered.
func TestLxUTLSKeyShareHandshake(t *testing.T) {
	for _, fingerprint := range []string{"chrome", "chrome_155", "firefox", "safari"} {
		for _, tc := range []struct {
			keyShare  string
			wantCurve stdtls.CurveID
		}{
			{C.RealityKeyShareClassical, stdtls.X25519},
			{C.RealityKeyShareDefault, stdtls.X25519MLKEM768},
		} {
			t.Run(fingerprint+"/"+tc.keyShare, func(t *testing.T) {
				client, server := lxReleasePair(t)
				result := lxKeyShareServe(t, server)
				config := lxNewKeyShareClient(t, lxKeyShareOptions(fingerprint, tc.keyShare, "h2"))
				conn, err := ClientHandshake(context.Background(), client, config)
				require.NoError(t, err)
				defer conn.Close()
				served := <-result
				require.NoError(t, served.err)
				require.Equal(t, tc.wantCurve, served.curve)
				if tc.keyShare == C.RealityKeyShareClassical {
					require.NotContains(t, served.offeredGroups, stdtls.X25519MLKEM768, "a hybrid group left in supported_groups invites a HelloRetryRequest")
				}
				require.Equal(t, "h2", conn.ConnectionState().NegotiatedProtocol)
				lxEcho(t, conn)
			})
		}
	}
}

// "hybrid" is a check: a no-op on a fingerprint with the share, an error naming
// the fingerprint on one without it (edge = Edge 85, X25519 only).
func TestLxUTLSKeyShareHybridRequiresShare(t *testing.T) {
	t.Parallel()
	hello := lxKeyShareHello(t, lxNewKeyShareClient(t, lxKeyShareOptions("chrome", C.RealityKeyShareHybrid, "h2"))).HandshakeState.Hello
	hybridIndex, _ := lxIndexOfShare(hello.KeyShares, utls.X25519MLKEM768)
	require.NotEqual(t, -1, hybridIndex)

	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	tlsConn, err := lxNewKeyShareClient(t, lxKeyShareOptions("edge", C.RealityKeyShareHybrid, "h2")).Client(conn)
	require.NoError(t, err)
	err = tlsConn.HandshakeContext(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "carries no X25519MLKEM768 key share")
	require.Contains(t, err.Error(), "Edge")
}

// Load-time errors: typos, the REALITY overlap and classical with ECH.
func TestLxUTLSKeyShareRejected(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"classic", "mlkem", "Hybrid", "auto"} {
		_, err := NewClient(context.Background(), logger.NOP(), "example.com", lxKeyShareOptions("chrome", value))
		require.Error(t, err, value)
		require.Contains(t, err.Error(), "unknown utls key_share", value)
	}

	reality := lxRealityOptions("chrome", "", false, false)
	reality.UTLS.KeyShare = C.RealityKeyShareClassical
	_, err := NewClient(context.Background(), logger.NOP(), "www.example.com", reality)
	require.ErrorContains(t, err, "use reality.key_share")

	ech := lxKeyShareOptions("chrome", C.RealityKeyShareClassical)
	ech.ECH = &option.OutboundECHOptions{Enabled: true}
	_, err = NewClient(context.Background(), logger.NOP(), "example.com", ech)
	require.ErrorContains(t, err, "unsupported with ECH")
}

// Clone() must carry the policy: outbounds clone the TLS config per dial.
func TestLxUTLSKeyShareSurvivesClone(t *testing.T) {
	t.Parallel()
	cloned, isUTLS := lxNewKeyShareClient(t, lxKeyShareOptions("chrome", C.RealityKeyShareClassical, "h2")).Clone().(*UTLSClientConfig)
	require.True(t, isUTLS)
	require.Equal(t, C.RealityKeyShareClassical, cloned.keyShare)
	hybridIndex, _ := lxIndexOfShare(lxKeyShareHello(t, cloned).HandshakeState.Hello.KeyShares, utls.X25519MLKEM768)
	require.Equal(t, -1, hybridIndex)
}

// lx:end SPEC 156 tests
