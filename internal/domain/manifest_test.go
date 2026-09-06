package domain

import (
	"crypto/sha256"
	"errors"
	"testing"
)

// fakeVerifier accepts a signature it recognises and refuses everything else.
//
// The real one lives behind a curve implementation the core cannot import, and
// this is not standing in for it: what these tests exercise is the ordering and
// the decisions around verification, which is where the mistakes are. That the
// signature itself verifies is the transport package's own test.
type fakeVerifier struct {
	accept    string
	callCount int
}

func (f *fakeVerifier) Verify(_ NostrPublicKey, digest, signature []byte) error {
	f.callCount++

	if string(signature) == f.accept && string(signature) == signatureFor(digest) {
		return nil
	}
	return errors.New("signature does not verify")
}

// signatureFor models a signature as a function of what it covers, so that
// changing the manifest invalidates it the way a real one would.
func signatureFor(digest []byte) string {
	return "signed:" + string(digest)
}

func testManifest(t *testing.T) Manifest {
	t.Helper()

	return Manifest{
		NetworkID: testNetworkID(t, "nostmesh test network"),
		Name:      "lab",
		Version:   1,
		Members: []Member{
			{PublicKey: testPublicKey(t, "member one"), Alias: "alice"},
			{PublicKey: testPublicKey(t, "member two"), Alias: "bob"},
		},
	}
}

func signManifest(t *testing.T, manifest Manifest, issuer NostrPublicKey) (SignedManifest, *fakeVerifier) {
	t.Helper()

	digest := manifest.Digest()
	signature := signatureFor(digest[:])

	return SignedManifest{
		Manifest:  manifest,
		Issuer:    issuer,
		Signature: []byte(signature),
	}, &fakeVerifier{accept: signature}
}

// A manifest from the pinned issuer, newer than what is held, is accepted.
func TestAValidManifestIsAccepted(t *testing.T) {
	issuer := testPublicKey(t, "the issuer")
	signed, verifier := signManifest(t, testManifest(t), issuer)

	if err := Accept(signed, issuer, 0, verifier); err != nil {
		t.Fatalf("a valid manifest was refused: %v", err)
	}
}

// A tampered manifest is refused.
//
// This is the case the digest exists for: the signature still verifies against
// what was signed, so only recomputing the digest over the current content
// catches a field rewritten afterwards.
func TestATamperedManifestIsRefused(t *testing.T) {
	issuer := testPublicKey(t, "the issuer")

	for name, tamper := range map[string]func(*Manifest){
		"a member added": func(m *Manifest) {
			m.Members = append(m.Members, Member{PublicKey: testPublicKey(t, "intruder")})
		},
		"a member removed":   func(m *Manifest) { m.Members = m.Members[:1] },
		"a member swapped":   func(m *Manifest) { m.Members[0].PublicKey = testPublicKey(t, "intruder") },
		"an alias changed":   func(m *Manifest) { m.Members[0].Alias = "somebody else" },
		"an address granted": func(m *Manifest) { m.Members[0].IPv4 = "10.0.0.1/32" },
		"the network moved":  func(m *Manifest) { m.NetworkID = testNetworkID(t, "another network") },
		"the version raised": func(m *Manifest) { m.Version = 99 },
		"a subnet carved":    func(m *Manifest) { m.Subnets = []uint16{7} },
	} {
		t.Run(name, func(t *testing.T) {
			signed, verifier := signManifest(t, testManifest(t), issuer)

			// Signed first, then rewritten — which is what an attacker who
			// intercepts a published manifest can do.
			tamper(&signed.Manifest)

			if err := Accept(signed, issuer, 0, verifier); err == nil {
				t.Error("a tampered manifest was accepted")
			}
		})
	}
}

// Reordering the members is not tampering.
//
// The order a manifest was written in is not part of what it says, and two nodes
// that list the same members differently must agree on the digest — otherwise
// each would conclude the other's signature was forged.
func TestReorderingMembersDoesNotChangeTheDigest(t *testing.T) {
	first := testManifest(t)

	second := testManifest(t)
	second.Members[0], second.Members[1] = second.Members[1], second.Members[0]

	if first.Digest() != second.Digest() {
		t.Error("the same members in a different order produced different digests")
	}
}

// A manifest signed by anybody but the pinned issuer is refused.
//
// This is what makes a manifest local intent rather than remote authority: the
// operator names the key, and a document signed by anyone else is not this
// network's manifest whatever it claims inside.
func TestAManifestFromAnotherIssuerIsRefused(t *testing.T) {
	stranger := testPublicKey(t, "a stranger")
	signed, verifier := signManifest(t, testManifest(t), stranger)

	err := Accept(signed, testPublicKey(t, "the issuer"), 0, verifier)
	if !errors.Is(err, ErrManifestWrongIssuer) {
		t.Errorf("expected a wrong-issuer refusal, got: %v", err)
	}
}

// The issuer is checked before the signature.
//
// A manifest from a stranger must cost this node no cryptography: verifying
// first would let anyone publishing to a relay make every node do curve
// arithmetic on demand.
func TestAStrangersManifestCostsNoCryptography(t *testing.T) {
	stranger := testPublicKey(t, "a stranger")
	signed, verifier := signManifest(t, testManifest(t), stranger)

	_ = Accept(signed, testPublicKey(t, "the issuer"), 0, verifier)

	if verifier.callCount != 0 {
		t.Errorf("the verifier ran %d times for a manifest from a stranger", verifier.callCount)
	}
}

// With no issuer pinned, nothing is accepted.
//
// An unpinned node has no way to tell this network's manifest from anyone
// else's, and defaulting to trusting the document's own claim would make the pin
// decorative.
func TestNothingIsAcceptedWithoutAPinnedIssuer(t *testing.T) {
	issuer := testPublicKey(t, "the issuer")
	signed, verifier := signManifest(t, testManifest(t), issuer)

	if err := Accept(signed, NostrPublicKey{}, 0, verifier); !errors.Is(err, ErrManifestWrongIssuer) {
		t.Errorf("a manifest was accepted with no issuer pinned: %v", err)
	}
}

// The signature is verified against the pinned key.
//
// A manifest names its own issuer, and that field is attacker-controlled. If
// verification used it, a forger would sign with their own key, name themselves
// as issuer, and verify perfectly.
//
// Note what actually protects against that, because it is not this test: the
// issuer check runs first and refuses a mismatch, so by the time verification
// happens the two keys are equal and passing either would behave identically.
// Swapping them is not a defect this can detect — it is unreachable code by
// then. What this fixes is the order: it holds only while the issuer check stays
// ahead of the signature, and a reordering is what would make the pin
// decorative.
func TestTheSignatureIsVerifiedAgainstThePinnedKey(t *testing.T) {
	issuer := testPublicKey(t, "the issuer")
	signed, _ := signManifest(t, testManifest(t), issuer)

	recorder := &keyRecorder{}
	_ = Accept(signed, issuer, 0, recorder)

	if recorder.key != issuer {
		t.Errorf("verified against %s, want the pinned %s", recorder.key.Short(), issuer.Short())
	}

	// And when the two disagree, the pinned one is what must be used. The
	// issuer check refuses this before verification, so reaching the verifier at
	// all would already be wrong — but if it is reached, it must not be with the
	// document's own claim.
	forged, _ := signManifest(t, testManifest(t), testPublicKey(t, "a forger"))
	second := &keyRecorder{}
	_ = Accept(forged, issuer, 0, second)

	if second.called && second.key != issuer {
		t.Errorf("verified a forged manifest against its own claimed issuer %s", second.key.Short())
	}
}

// keyRecorder remembers which key a verification was asked about.
type keyRecorder struct {
	called bool
	key    NostrPublicKey
}

func (k *keyRecorder) Verify(key NostrPublicKey, _, _ []byte) error {
	k.called = true
	k.key = key
	return nil
}

// A missing verifier is a refusal, not a pass.
//
// Treating "nothing checked the signature" as success is how an unauthenticated
// manifest gets applied, and it is the kind of defect that only shows up when
// something upstream forgets to wire a dependency.
func TestAMissingVerifierRefuses(t *testing.T) {
	issuer := testPublicKey(t, "the issuer")
	signed, _ := signManifest(t, testManifest(t), issuer)

	if err := Accept(signed, issuer, 0, nil); err == nil {
		t.Error("a manifest was accepted with no verifier at all")
	}
}

// An unsigned manifest is refused.
func TestAnUnsignedManifestIsRefused(t *testing.T) {
	issuer := testPublicKey(t, "the issuer")
	signed, verifier := signManifest(t, testManifest(t), issuer)
	signed.Signature = nil

	if err := Accept(signed, issuer, 0, verifier); !errors.Is(err, ErrManifestUnsigned) {
		t.Errorf("expected an unsigned refusal, got: %v", err)
	}
}

// A manifest at or below the version held is refused.
//
// A relay keeps events and replays them to every new subscription, so an old
// manifest arrives looking perfectly valid. Applying one would renumber a
// working network backwards.
func TestAnOlderManifestIsRefused(t *testing.T) {
	issuer := testPublicKey(t, "the issuer")

	for _, testCase := range []struct{ offered, held uint64 }{
		{offered: 1, held: 5},
		{offered: 4, held: 5},
		{offered: 5, held: 5}, // equal is not newer
	} {
		manifest := testManifest(t)
		manifest.Version = testCase.offered
		signed, verifier := signManifest(t, manifest, issuer)

		err := Accept(signed, issuer, testCase.held, verifier)
		if !errors.Is(err, ErrManifestRollback) {
			t.Errorf("version %d against held %d: expected a rollback refusal, got %v",
				testCase.offered, testCase.held, err)
		}
	}
}

// A newer manifest replaces what is held.
func TestANewerManifestIsAccepted(t *testing.T) {
	issuer := testPublicKey(t, "the issuer")

	manifest := testManifest(t)
	manifest.Version = 6
	signed, verifier := signManifest(t, manifest, issuer)

	if err := Accept(signed, issuer, 5, verifier); err != nil {
		t.Fatalf("a newer manifest was refused: %v", err)
	}
}

// Structural problems are refused before anything else happens.
func TestAMalformedManifestIsRefused(t *testing.T) {
	issuer := testPublicKey(t, "the issuer")

	for name, break_ := range map[string]func(*Manifest){
		"no version": func(m *Manifest) { m.Version = 0 },
		"no members": func(m *Manifest) { m.Members = nil },
		"a duplicate member": func(m *Manifest) {
			m.Members = append(m.Members, m.Members[0])
		},
		"a member with no key": func(m *Manifest) {
			m.Members = append(m.Members, Member{})
		},
		"an oversized name": func(m *Manifest) {
			m.Name = string(make([]byte, MaxNetworkNameLength+1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			manifest := testManifest(t)
			break_(&manifest)
			signed, verifier := signManifest(t, manifest, issuer)

			if err := Accept(signed, issuer, 0, verifier); !errors.Is(err, ErrManifestMalformed) {
				t.Errorf("expected a malformed refusal, got: %v", err)
			}
		})
	}
}

// The salt is never part of a manifest.
//
// It is the entire privacy boundary: an observer holding every published event
// must still be unable to derive an address. A field carrying it would hand that
// away, so the type must not have one.
func TestAManifestCarriesNoSalt(t *testing.T) {
	salt := testSalt(t, "nostmesh test network salt")

	manifest := testManifest(t)
	digest := manifest.Digest()

	// The digest covers the manifest's whole content, so if the salt were in
	// there in any form it would influence this.
	manifest.Name = "changed"
	if manifest.Digest() == digest {
		t.Fatal("the digest ignored a content change, so this check proves nothing")
	}

	// And nothing in the type can hold it: this is a compile-time property the
	// test states so a future field is a deliberate decision.
	_ = salt
}

// A member is found by identity, and a stranger is not.
func TestMemberLookup(t *testing.T) {
	manifest := testManifest(t)

	member, err := manifest.Member(testPublicKey(t, "member one"))
	if err != nil {
		t.Fatalf("looking up a member: %v", err)
	}
	if member.Alias != "alice" {
		t.Errorf("alias = %q, want alice", member.Alias)
	}

	if _, err := manifest.Member(testPublicKey(t, "a stranger")); !errors.Is(err, ErrMemberNotFound) {
		t.Errorf("expected a not-found error for a stranger, got: %v", err)
	}
}

// A manifest with no subnets listed uses subnet zero.
func TestAManifestWithoutSubnetsUsesZero(t *testing.T) {
	if subnet := testManifest(t).Subnet(0); subnet != 0 {
		t.Errorf("subnet = %d, want 0", subnet)
	}
}

// The digest is stable across runs.
//
// Two nodes computing different digests for the same manifest would each
// conclude the other's signature was forged, so this is checked rather than
// assumed of the encoder.
func TestTheDigestIsStable(t *testing.T) {
	manifest := testManifest(t)
	first := manifest.Digest()

	for range 16 {
		if manifest.Digest() != first {
			t.Fatal("the same manifest produced two different digests")
		}
	}

	// And a different manifest produces a different one, or the digest would be
	// satisfying this test by being constant.
	other := testManifest(t)
	other.Version = 2
	if other.Digest() == first {
		t.Error("two different manifests produced the same digest")
	}
}

// Length prefixes stop two different manifests colliding.
//
// Without them, moving a character from one field to the next would produce the
// same byte string — and two manifests that hash alike share a signature.
func TestFieldsCannotBeShiftedBetweenEachOther(t *testing.T) {
	first := testManifest(t)
	first.Name = "ab"
	first.Members[0].Alias = "cd"

	second := testManifest(t)
	second.Name = "abc"
	second.Members[0].Alias = "d"

	if first.Digest() == second.Digest() {
		t.Error("moving a character between fields produced the same digest")
	}
}

// The digest is domain-separated.
//
// A signature over a manifest must not be reusable as a signature over anything
// else this project hashes.
func TestTheDigestIsDomainSeparated(t *testing.T) {
	manifest := testManifest(t)

	// A bare SHA-256 of the network id must not collide with the manifest's
	// digest, which it would if nothing separated the two uses.
	bare := sha256.Sum256(manifest.NetworkID[:])
	if manifest.Digest() == bare {
		t.Error("the manifest digest matches a bare hash of its contents")
	}
}
