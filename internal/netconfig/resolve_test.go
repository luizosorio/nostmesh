package netconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/luizosorio/nostmesh/internal/config"
	"github.com/luizosorio/nostmesh/internal/domain"
)

// acceptingVerifier stands in for the signature check.
//
// The real one lives behind a curve the core cannot import. What these tests
// exercise is which address a node ends up with, and the signature's own
// correctness is asserted where it belongs.
type acceptingVerifier struct{ refuse bool }

func (a acceptingVerifier) Verify(domain.NostrPublicKey, []byte, []byte) error {
	if a.refuse {
		return errors.New("signature does not verify")
	}
	return nil
}

func testKey(t *testing.T, seed string) domain.NostrPublicKey {
	t.Helper()

	digest := sha256.Sum256([]byte(seed))
	key, err := domain.ParseNostrPublicKey(hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatalf("building key: %v", err)
	}
	return key
}

func testSaltHex(seed string) string {
	digest := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(digest[:])
}

// writeManifest puts a signed manifest on disk and returns its path.
func writeManifest(t *testing.T, signed domain.SignedManifest) string {
	t.Helper()

	encoded, err := json.MarshalIndent(encodeDocument(signed), "", "  ")
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}

	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	return path
}

func testSignedManifest(t *testing.T, issuer domain.NostrPublicKey, members ...string) domain.SignedManifest {
	t.Helper()

	networkSeed := sha256.Sum256([]byte("test network"))
	networkID, err := domain.NewNetworkID(networkSeed[:])
	if err != nil {
		t.Fatalf("building network id: %v", err)
	}

	entries := make([]domain.Member, 0, len(members))
	for _, seed := range members {
		entries = append(entries, domain.Member{PublicKey: testKey(t, seed), Alias: seed})
	}

	return domain.SignedManifest{
		Manifest: domain.Manifest{
			NetworkID: networkID,
			Name:      "lab",
			Version:   1,
			Members:   entries,
		},
		Issuer:    issuer,
		Signature: []byte("a signature"),
	}
}

// A node without a network keeps the address it was configured with.
//
// This is the criterion NM-21 states as preserving MVP 1: every deployment
// before derived addressing wrote its address in the file, and adding a feature
// they did not enable must change nothing for them.
func TestANodeWithoutANetworkKeepsItsManualAddress(t *testing.T) {
	cfg := config.Default()
	cfg.Node.OverlayAddress = "100.96.0.1/32"

	resolution, err := Resolve(cfg, testKey(t, "self"), acceptingVerifier{})
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}

	if resolution.Derived {
		t.Error("a node with no network reported a derived address")
	}
	if resolution.Address.String() != "100.96.0.1/32" {
		t.Errorf("address = %s, want the configured 100.96.0.1/32", resolution.Address)
	}
}

// A node with a network derives its address from the manifest.
func TestANodeWithANetworkDerivesItsAddress(t *testing.T) {
	issuer := testKey(t, "the issuer")
	self := testKey(t, "self")

	cfg := config.Default()
	cfg.Network = config.Network{
		Manifest: writeManifest(t, testSignedManifest(t, issuer, "self", "other")),
		Issuer:   issuer.String(),
		Salt:     testSaltHex("network salt"),
	}

	resolution, err := Resolve(cfg, self, acceptingVerifier{})
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}

	if !resolution.Derived {
		t.Fatal("a node with a network reported a manually configured address")
	}
	if !resolution.Address.Addr().Is6() {
		t.Errorf("derived %s, which is not IPv6", resolution.Address)
	}
	if !resolution.Address.Addr().IsPrivate() {
		t.Errorf("derived %s, which is not a private address", resolution.Address)
	}
	if len(resolution.Allocation.Assignments) != 2 {
		t.Errorf("the allocation has %d entries for a two-member network",
			len(resolution.Allocation.Assignments))
	}
}

// A configured network overrides a manual address rather than merging with it.
//
// Both being set is a configuration an operator can write, and silently
// installing the manual one would put the node off its network while its
// configuration says otherwise.
func TestAConfiguredNetworkWinsOverAManualAddress(t *testing.T) {
	issuer := testKey(t, "the issuer")

	cfg := config.Default()
	cfg.Node.OverlayAddress = "100.96.0.1/32"
	cfg.Network = config.Network{
		Manifest: writeManifest(t, testSignedManifest(t, issuer, "self")),
		Issuer:   issuer.String(),
		Salt:     testSaltHex("network salt"),
	}

	resolution, err := Resolve(cfg, testKey(t, "self"), acceptingVerifier{})
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}

	if !resolution.Derived {
		t.Error("the manually configured address won over the configured network")
	}
	if resolution.Address.String() == "100.96.0.1/32" {
		t.Error("the node installed its manual address despite being on a network")
	}
}

// A network that cannot be loaded fails rather than falling back.
//
// Falling back would leave an operator with a node that is not on the network
// they configured, reporting nothing about it — which is worse than not starting.
func TestABrokenNetworkDoesNotFallBackToManual(t *testing.T) {
	issuer := testKey(t, "the issuer")

	for name, breakIt := range map[string]func(*config.Config){
		"the manifest is missing": func(c *config.Config) {
			c.Network.Manifest = filepath.Join(t.TempDir(), "absent.json")
		},
		"the salt is not hex":     func(c *config.Config) { c.Network.Salt = "not hex" },
		"the salt is short":       func(c *config.Config) { c.Network.Salt = "abcd" },
		"the issuer is not a key": func(c *config.Config) { c.Network.Issuer = "nonsense" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Node.OverlayAddress = "100.96.0.1/32" // a fallback that must not be taken
			cfg.Network = config.Network{
				Manifest: writeManifest(t, testSignedManifest(t, issuer, "self")),
				Issuer:   issuer.String(),
				Salt:     testSaltHex("network salt"),
			}
			breakIt(&cfg)

			resolution, err := Resolve(cfg, testKey(t, "self"), acceptingVerifier{})
			if err == nil {
				t.Fatalf("a broken network resolved to %s instead of failing", resolution.Address)
			}
			if resolution.Address.IsValid() {
				t.Errorf("a failed resolution still returned an address: %s", resolution.Address)
			}
		})
	}
}

// A manifest whose signature does not verify is refused.
func TestAnUnverifiedManifestIsRefused(t *testing.T) {
	issuer := testKey(t, "the issuer")

	cfg := config.Default()
	cfg.Network = config.Network{
		Manifest: writeManifest(t, testSignedManifest(t, issuer, "self")),
		Issuer:   issuer.String(),
		Salt:     testSaltHex("network salt"),
	}

	if _, err := Resolve(cfg, testKey(t, "self"), acceptingVerifier{refuse: true}); err == nil {
		t.Error("a manifest with an unverifiable signature was accepted")
	}
}

// A node absent from its own network's manifest is told so.
//
// It would otherwise derive nothing and fail later somewhere that cannot explain
// why — most likely as an interface with no address.
func TestANodeMissingFromTheManifestIsReported(t *testing.T) {
	issuer := testKey(t, "the issuer")

	cfg := config.Default()
	cfg.Network = config.Network{
		Manifest: writeManifest(t, testSignedManifest(t, issuer, "somebody", "else")),
		Issuer:   issuer.String(),
		Salt:     testSaltHex("network salt"),
	}

	_, err := Resolve(cfg, testKey(t, "self"), acceptingVerifier{})
	if !errors.Is(err, domain.ErrNotAMember) {
		t.Errorf("expected a not-a-member error, got: %v", err)
	}
}

// A node with neither a network nor an address says so distinctly.
func TestANodeWithNoAddressAtAll(t *testing.T) {
	_, err := Resolve(config.Default(), testKey(t, "self"), acceptingVerifier{})

	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("expected ErrNotConfigured, got: %v", err)
	}
}

// Two nodes reading the same manifest agree on every address.
//
// This is what makes derivation work at all: a member computes a peer's address
// rather than being told it, so a disagreement would mean two nodes each
// believing the other is somewhere it is not.
func TestTwoNodesAgreeOnEveryAddress(t *testing.T) {
	issuer := testKey(t, "the issuer")
	path := writeManifest(t, testSignedManifest(t, issuer, "alice", "bob", "carol"))

	cfg := config.Default()
	cfg.Network = config.Network{
		Manifest: path,
		Issuer:   issuer.String(),
		Salt:     testSaltHex("network salt"),
	}

	alice, err := Resolve(cfg, testKey(t, "alice"), acceptingVerifier{})
	if err != nil {
		t.Fatalf("resolving for alice: %v", err)
	}
	bob, err := Resolve(cfg, testKey(t, "bob"), acceptingVerifier{})
	if err != nil {
		t.Fatalf("resolving for bob: %v", err)
	}

	// Each node's own address must be what the other computed for it.
	bobsViewOfAlice, err := bob.Allocation.For(testKey(t, "alice"))
	if err != nil {
		t.Fatalf("looking up alice in bob's table: %v", err)
	}
	if bobsViewOfAlice.Address != alice.Address.Addr() {
		t.Errorf("alice installed %s, bob expects her at %s",
			alice.Address.Addr(), bobsViewOfAlice.Address)
	}

	alicesViewOfBob, err := alice.Allocation.For(testKey(t, "bob"))
	if err != nil {
		t.Fatalf("looking up bob in alice's table: %v", err)
	}
	if alicesViewOfBob.Address != bob.Address.Addr() {
		t.Errorf("bob installed %s, alice expects him at %s",
			bob.Address.Addr(), alicesViewOfBob.Address)
	}
}

// A manifest survives a round trip through its file format.
//
// The document shape exists because the domain types render as lists of numbers
// in JSON. Encoding and decoding must agree exactly, or a manifest written by
// one version verifies against nothing.
func TestAManifestRoundTripsThroughItsFileFormat(t *testing.T) {
	issuer := testKey(t, "the issuer")
	original := testSignedManifest(t, issuer, "alice", "bob")
	original.Manifest.Members[0].IPv4 = "10.0.0.1/32"
	original.Manifest.Subnets = []uint16{3}

	loaded, err := LoadManifest(writeManifest(t, original))
	if err != nil {
		t.Fatalf("loading: %v", err)
	}

	if loaded.Manifest.Digest() != original.Manifest.Digest() {
		t.Error("the manifest's digest changed across a round trip, so a signature over it would no longer verify")
	}
	if loaded.Issuer != original.Issuer {
		t.Error("the issuer changed across a round trip")
	}
	if string(loaded.Signature) != string(original.Signature) {
		t.Error("the signature changed across a round trip")
	}
}

// A manifest file that does not parse is refused rather than half-read.
func TestAMalformedManifestFileIsRefused(t *testing.T) {
	for name, content := range map[string]string{
		"not json":           "this is not json",
		"a truncated object": `{"manifest":`,
		"a bad network id":   `{"manifest":{"network_id":"zz","version":1,"members":[]},"issuer":"","signature":""}`,
		"a bad member key":   `{"manifest":{"network_id":"` + testSaltHex("n") + `","version":1,"members":[{"public_key":"zz"}]},"issuer":"` + testSaltHex("i") + `","signature":""}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatalf("writing: %v", err)
			}

			if _, err := LoadManifest(path); err == nil {
				t.Error("a malformed manifest file was accepted")
			}
		})
	}
}
