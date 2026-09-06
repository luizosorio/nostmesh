package observability

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/luizosorio/nostmesh/internal/domain"
	"github.com/luizosorio/nostmesh/internal/protocol"
)

// secretScan holds every encoding a key might be recognised in.
//
// Testing one encoding is how a leak in another survives: a key rendered as
// base64 is invisible to a scan that looks only for hex, and both are things a
// struct tag or a formatting verb might produce.
type secretScan struct {
	forbidden map[string]string
}

func newSecretScan(t *testing.T, secrets map[string][]byte) secretScan {
	t.Helper()

	forbidden := make(map[string]string, len(secrets)*4)
	for name, raw := range secrets {
		if len(raw) == 0 {
			t.Fatalf("%s is empty, so the scan would pass against anything", name)
		}
		forbidden[name+" raw"] = string(raw)
		forbidden[name+" hex"] = hex.EncodeToString(raw)
		forbidden[name+" base64"] = base64.StdEncoding.EncodeToString(raw)
		forbidden[name+" base64url"] = base64.RawURLEncoding.EncodeToString(raw)
	}
	return secretScan{forbidden: forbidden}
}

// leaked reports the encoding a secret was found in, if any.
func (s secretScan) leaked(content string) (string, bool) {
	for encoding, secret := range s.forbidden {
		if strings.Contains(content, secret) {
			return encoding, true
		}
	}
	return "", false
}

func (s secretScan) assertClean(t *testing.T, label, content string) {
	t.Helper()

	if encoding, found := s.leaked(content); found {
		t.Errorf("%s contains a secret as %s", label, encoding)
	}
}

// keyMaterial builds a private key pair and the scan that hunts for it.
func keyMaterial(t *testing.T) (domain.NostrPrivateKey, domain.WireGuardPrivateKey, secretScan) {
	t.Helper()

	nostrRaw := make([]byte, domain.NostrKeySize)
	if _, err := rand.Read(nostrRaw); err != nil {
		t.Fatalf("generating: %v", err)
	}
	wireguardRaw := make([]byte, domain.WireGuardKeySize)
	if _, err := rand.Read(wireguardRaw); err != nil {
		t.Fatalf("generating: %v", err)
	}

	nostrKey, err := domain.NewNostrPrivateKey(nostrRaw)
	if err != nil {
		t.Fatalf("building the nostr key: %v", err)
	}
	wireguardKey, err := domain.NewWireGuardPrivateKey(wireguardRaw)
	if err != nil {
		t.Fatalf("building the wireguard key: %v", err)
	}

	scan := newSecretScan(t, map[string][]byte{
		"the nostr private key":     nostrRaw,
		"the wireguard private key": wireguardRaw,
	})

	return nostrKey, wireguardKey, scan
}

// publicKeys builds a pair of public keys for rendering.
//
// Derived from a visible seed rather than written as literals: a secret scanner
// cannot tell a public key from a private one — both are 32 bytes in the same
// encodings — so the distinction is the project's to make, and a derived value
// is one nobody has to classify.
func publicKeys(t *testing.T) (domain.NostrPublicKey, domain.WireGuardPublicKey) {
	t.Helper()

	nostrSeed := sha256.Sum256([]byte("observability test nostr public key"))
	wireguardSeed := sha256.Sum256([]byte("observability test wireguard public key"))

	nostrPublic, err := domain.ParseNostrPublicKey(hex.EncodeToString(nostrSeed[:]))
	if err != nil {
		t.Fatalf("building the nostr public key: %v", err)
	}
	wireguardPublic, err := domain.ParseWireGuardPublicKey(base64.StdEncoding.EncodeToString(wireguardSeed[:]))
	if err != nil {
		t.Fatalf("building the wireguard public key: %v", err)
	}

	return nostrPublic, wireguardPublic
}

// A private key handed to the logger is redacted rather than written.
//
// The domain types already redact through LogValue. This asserts the property
// end to end, through a real handler, because that is where it has to hold.
func TestAPrivateKeyIsNeverWritten(t *testing.T) {
	nostrKey, wireguardKey, scan := keyMaterial(t)

	var out bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&out, nil))

	log.Info("a record that should not carry key material",
		"nostr_private", nostrKey,
		"wireguard_private", wireguardKey,
		"nostr_string", nostrKey.String(),
		"wireguard_string", wireguardKey.String(),
	)

	scan.assertClean(t, "the log line", out.String())
}

// The scan must find a secret that is genuinely present.
//
// Without this the test above proves nothing: a scan that matches nothing passes
// against every input, and would keep passing after a redaction was removed.
func TestTheScanDetectsAPlantedSecret(t *testing.T) {
	nostrRaw := make([]byte, domain.NostrKeySize)
	if _, err := rand.Read(nostrRaw); err != nil {
		t.Fatalf("generating: %v", err)
	}
	scan := newSecretScan(t, map[string][]byte{"the nostr private key": nostrRaw})

	var out bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&out, nil))

	// Logged deliberately, the way a struct tag or a formatting verb would.
	log.Info("a record carrying key material", "leaked", hex.EncodeToString(nostrRaw))

	if _, found := scan.leaked(out.String()); !found {
		t.Error("the scan missed a secret written straight into the record, so it proves nothing about the records that pass")
	}
}

// No attribute constructor emits key material.
//
// The constructors are the chokepoint every call site goes through, so proving
// the property here is what makes it hold everywhere it is used.
func TestNoAttributeConstructorEmitsKeyMaterial(t *testing.T) {
	_, _, scan := keyMaterial(t)
	nostrPublic, wireguardPublic := publicKeys(t)

	var out bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&out, nil))

	log.Info("every constructor at once",
		Node(nostrPublic),
		Peer(nostrPublic),
		TunnelKey(wireguardPublic),
		Session("0123456789abcdef0123456789abcdef"),
		Event("test.event"),
		Result(ResultOK),
		Reason(ReasonInternal),
		Endpoint(netip.MustParseAddrPort("203.0.113.7:51820"), DiagnosticAddresses),
		AllowedIPs([]netip.Prefix{netip.MustParsePrefix("100.96.0.2/32")}, DiagnosticAddresses),
	)

	scan.assertClean(t, "the constructors' output", out.String())
}

// An identifier is abbreviated rather than carried whole.
//
// A full public key is not a secret, but it is a durable handle for an identity,
// and a log that carries one becomes a correlation database. The operations
// documentation asks for the node identifier abbreviated for this reason.
func TestIdentifiersAreAbbreviated(t *testing.T) {
	public, _ := publicKeys(t)

	var out bytes.Buffer
	slog.New(slog.NewJSONHandler(&out, nil)).Info("identity", Peer(public))

	if strings.Contains(out.String(), public.String()) {
		t.Error("the full public key reached the log; a log carrying whole identifiers is a correlation database")
	}
	if !strings.Contains(out.String(), public.Short()) {
		t.Errorf("the abbreviated key is missing, so the line cannot be correlated at all: %s", out.String())
	}
}

// The ciphertext of a message never reaches a log.
//
// This is the rule the operations documentation states outright, and the
// envelope renderer is the one place a body could slip through.
func TestTheEnvelopeBodyIsNeverWritten(t *testing.T) {
	body := "dGhpcyBpcyBjaXBoZXJ0ZXh0IHRoYXQgbXVzdCBuZXZlciBiZSBsb2dnZWQ="

	var out bytes.Buffer
	slog.New(slog.NewJSONHandler(&out, nil)).Info("received",
		"envelope", EnvelopeAttrs{Envelope: protocol.Envelope{
			Version:   protocol.Version,
			Namespace: protocol.Namespace,
			Type:      protocol.TypeSessionRequest,
			MessageID: "0123456789abcdef",
			SessionID: "fedcba9876543210",
			Body:      body,
		}},
	)

	if strings.Contains(out.String(), body) {
		t.Error("the encrypted body reached the log")
	}

	// What replaces it has to be enough to recognise the same message on the
	// other host, or the rule costs the diagnosis it was protecting.
	if !strings.Contains(out.String(), "body_digest") {
		t.Error("the body was dropped without a digest, so the message cannot be correlated across hosts")
	}
	if !strings.Contains(out.String(), "body_len") {
		t.Error("the body was dropped without its length")
	}
}

// The digest must actually distinguish two different bodies.
//
// A digest that collapsed to a constant would satisfy the test above while
// telling a reader nothing, which is the failure worth guarding.
func TestTheBodyDigestDistinguishesMessages(t *testing.T) {
	first := digestOf("one ciphertext")
	second := digestOf("another ciphertext")

	if first == second {
		t.Error("two different bodies produced the same digest, so it cannot correlate anything")
	}
	if first == "" {
		t.Error("a non-empty body produced an empty digest")
	}
	if digestOf("") != "" {
		t.Error("an absent body produced a digest, which would look like a message that carried one")
	}
}

// A candidate list must actually render its candidates.
//
// This was a real defect, found by reading the output rather than the code: the
// candidates were built as slog.Value groups inside a slice, and the JSON
// handler does not resolve those — every candidate marshalled as "{}". The count
// was right, the list was empty, and the single most useful field at debug said
// nothing while looking like it was working.
func TestCandidatesAreRenderedNotEmptied(t *testing.T) {
	var out bytes.Buffer
	slog.New(slog.NewJSONHandler(&out, nil)).Info("update",
		"negotiation", NegotiationAttrs{
			Payload: protocol.Payload{Candidate: &protocol.CandidateUpdate{
				Added: []protocol.Candidate{{
					ID: "c1", Type: "srflx", Transport: "udp",
					Address: "203.0.113.7:51820", Priority: 200,
				}},
			}},
			Mode: DiagnosticAddresses,
		},
	)

	rendered := out.String()
	if strings.Contains(rendered, `"candidates":[{}]`) {
		t.Fatalf("candidates rendered as empty objects: %s", rendered)
	}
	for _, want := range []string{"c1", "srflx", "203.0.113.7:51820", "200"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("the candidate is missing %q, so the list says nothing: %s", want, rendered)
		}
	}
}

// Capabilities must render too, for the same reason.
func TestCapabilitiesAreRendered(t *testing.T) {
	var out bytes.Buffer
	slog.New(slog.NewJSONHandler(&out, nil)).Info("request",
		"negotiation", NegotiationAttrs{
			Payload: protocol.Payload{Request: &protocol.SessionRequest{
				Capabilities: protocol.Capabilities{
					ProtocolVersions: []int{1},
					Transports:       []string{"wireguard"},
				},
			}},
		},
	)

	if !strings.Contains(out.String(), "wireguard") {
		t.Errorf("the declared transports did not render: %s", out.String())
	}
}
