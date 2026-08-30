package protocol

// Golden vectors for the control protocol.
//
// These pin the wire format so that an accidental change to a field name, an
// encoding or a validation rule fails a test rather than silently breaking
// interoperability with a peer running a different build.
//
// They carry no real key material: every key and identifier is derived from a
// visible seed, so a scanner cannot mistake them for credentials and a reader
// cannot mistake them for something that must be protected.
