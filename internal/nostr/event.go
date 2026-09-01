package nostr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/luizosorio/nostmesh/internal/domain"
)

var (
	// ErrEventMalformed reports an event that is not shaped like NIP-01.
	ErrEventMalformed = errors.New("event is malformed")

	// ErrEventIDMismatch reports an event whose id is not the digest of its
	// own contents.
	//
	// The id is not an identifier the sender may choose: it is the hash of the
	// canonical serialization, and it is what the signature covers. An event
	// whose id does not recompute has had its contents changed after signing,
	// so accepting it would let a relay alter a message without invalidating
	// its signature.
	ErrEventIDMismatch = errors.New("event id does not match its contents")
)

// Event is a NIP-01 event.
//
// Field names and order follow the specification exactly. The id and signature
// are derived, never supplied: BuildEvent computes them and VerifyEvent
// recomputes them, so a value arriving from the wire is checked rather than
// trusted.
type Event struct {
	ID        string     `json:"id"`
	PublicKey string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Signature string     `json:"sig"`
}

// TagValue returns the first value of the first tag with the given name.
//
// NIP-01 tags are positional: the first element names the tag and the second
// carries its value. A tag that is present but has no value reports absent,
// because a caller asking for the value has nothing to do with an empty one.
func (e Event) TagValue(name string) (string, bool) {
	for _, tag := range e.Tags {
		if len(tag) >= 2 && tag[0] == name {
			return tag[1], true
		}
	}
	return "", false
}

// serializeForID produces the canonical form whose digest is the event id.
//
// NIP-01 fixes this as the JSON array [0, pubkey, created_at, kind, tags,
// content]. Nothing may be added, reordered or reformatted: every other
// implementation hashes exactly this, and an event serialized any other way
// carries an id no relay accepts.
func serializeForID(publicKey string, createdAt int64, kind int, tags [][]string, content string) ([]byte, error) {
	// Tags must serialize as [] rather than null: a nil slice encodes as null,
	// which hashes differently and produces an id no other implementation
	// agrees with.
	if tags == nil {
		tags = [][]string{}
	}

	serialized, err := json.Marshal([]any{0, publicKey, createdAt, kind, tags, content})
	if err != nil {
		return nil, fmt.Errorf("serializing event: %w", err)
	}
	return serialized, nil
}

// BuildEvent produces a signed NIP-01 event.
//
// The id and signature are computed here from the other fields, so a caller
// cannot construct an event whose id disagrees with its contents.
func BuildEvent(signer *Signer, kind int, tags [][]string, content string, createdAt time.Time) (Event, []byte, error) {
	if signer == nil {
		return Event{}, nil, errors.New("signer is required")
	}
	if tags == nil {
		tags = [][]string{}
	}

	publicKey := signer.PublicKey().String()
	timestamp := createdAt.Unix()

	serialized, err := serializeForID(publicKey, timestamp, kind, tags, content)
	if err != nil {
		return Event{}, nil, err
	}
	digest := sha256.Sum256(serialized)

	signature, err := signer.Sign(digest[:])
	if err != nil {
		return Event{}, nil, fmt.Errorf("signing event: %w", err)
	}

	event := Event{
		ID:        hex.EncodeToString(digest[:]),
		PublicKey: publicKey,
		CreatedAt: timestamp,
		Kind:      kind,
		Tags:      tags,
		Content:   content,
		Signature: hex.EncodeToString(signature),
	}

	raw, err := json.Marshal(event)
	if err != nil {
		return Event{}, nil, fmt.Errorf("encoding event: %w", err)
	}
	return event, raw, nil
}

// ParseEvent decodes an event without verifying it.
//
// Parsing and verification are separate so that the caller cannot accidentally
// act on a parsed-but-unverified event: everything that matters goes through
// VerifyEvent, and this returns only the shape.
func ParseEvent(raw []byte) (Event, error) {
	var event Event
	if err := json.Unmarshal(raw, &event); err != nil {
		return Event{}, fmt.Errorf("%w: %w", ErrEventMalformed, err)
	}
	if event.ID == "" || event.PublicKey == "" || event.Signature == "" {
		return Event{}, fmt.Errorf("%w: missing id, pubkey or signature", ErrEventMalformed)
	}
	return event, nil
}

// VerifyEvent checks that an event is authentic and unmodified.
//
// Both checks are required and neither substitutes for the other. Recomputing
// the id proves the contents are the ones that were hashed; verifying the
// signature proves the hash was signed by the claimed key. Checking only the
// signature would accept an event whose fields were rewritten around a valid
// signature of different contents.
func VerifyEvent(event Event) error {
	publicKey, err := domain.ParseNostrPublicKey(event.PublicKey)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrEventMalformed, err)
	}

	serialized, err := serializeForID(event.PublicKey, event.CreatedAt, event.Kind, event.Tags, event.Content)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(serialized)

	expectedID := hex.EncodeToString(digest[:])
	if event.ID != expectedID {
		return fmt.Errorf("%w: declared %s, computed %s", ErrEventIDMismatch, event.ID, expectedID)
	}

	signature, err := hex.DecodeString(event.Signature)
	if err != nil {
		return fmt.Errorf("%w: signature is not hex", ErrEventMalformed)
	}

	return Verify(publicKey, digest[:], signature)
}

// RecipientTag builds the NIP-01 "p" tag addressing a recipient.
//
// Relays index this tag, which is what lets a node subscribe to the events
// addressed to it rather than to everything of this kind.
func RecipientTag(recipient domain.NostrPublicKey) []string {
	return []string{"p", recipient.String()}
}

// ReplaceableTag builds the NIP-01 "d" tag identifying a replaceable event.
//
// Kinds in the 30000-39999 range are parameterized-replaceable: a relay keeps
// only the newest event per (author, kind, d) triple. The d value therefore
// decides what replaces what, and getting it wrong silently destroys messages —
// or, just as badly, silently preserves ones that should have been replaced.
//
// Within a session the value must distinguish every message: scoping by session
// alone would make an offer replace the request that prompted it, and scoping by
// session and type would make a second candidate update discard the first.
//
// Across sessions the opposite is needed. A session.request opens a conversation
// with one peer, and a newer request supersedes an older one completely — the
// earlier session is abandoned the moment its initiator tries again. Keeping
// both means a responder subscribing later finds two live requests and answers
// whichever the relay hands it first, which is how a peer ends up negotiating a
// session its counterpart has already given up on. So an opening message is
// keyed by recipient rather than by session: one live request per peer, always
// the newest.
func ReplaceableTag(sessionID string, messageType string, seq uint64) []string {
	return []string{"d", fmt.Sprintf("%s:%s:%d", sessionID, messageType, seq)}
}

// OpeningTag builds the "d" tag for a message that opens a conversation.
//
// Keyed by recipient, so a newer request replaces the one before it rather than
// accumulating alongside it. See ReplaceableTag for why the two differ.
func OpeningTag(recipient domain.NostrPublicKey, messageType string) []string {
	return []string{"d", fmt.Sprintf("open:%s:%s", recipient.String(), messageType)}
}
