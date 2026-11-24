//go:build dev

package devfake

import "encoding/binary"

// A minimal deterministic CBOR encoder (RFC 8949) for the shapes of an
// attestation document. Dev only: production never builds CBOR.

type cbor struct{ b []byte }

func (e *cbor) head(major byte, n uint64) {
	switch {
	case n < 24:
		e.b = append(e.b, major<<5|byte(n))
	case n <= 0xff:
		e.b = append(e.b, major<<5|24, byte(n))
	case n <= 0xffff:
		e.b = append(e.b, major<<5|25)
		e.b = binary.BigEndian.AppendUint16(e.b, uint16(n))
	case n <= 0xffffffff:
		e.b = append(e.b, major<<5|26)
		e.b = binary.BigEndian.AppendUint32(e.b, uint32(n))
	default:
		e.b = append(e.b, major<<5|27)
		e.b = binary.BigEndian.AppendUint64(e.b, n)
	}
}

func (e *cbor) uint(n uint64) { e.head(0, n) }

func (e *cbor) int(n int64) {
	if n >= 0 {
		e.head(0, uint64(n))
		return
	}
	e.head(1, uint64(-1-n))
}

func (e *cbor) bytes(b []byte) { e.head(2, uint64(len(b))); e.b = append(e.b, b...) }
func (e *cbor) text(s string)  { e.head(3, uint64(len(s))); e.b = append(e.b, s...) }
func (e *cbor) array(n int)    { e.head(4, uint64(n)) }
func (e *cbor) mapHead(n int)  { e.head(5, uint64(n)) }
func (e *cbor) null()          { e.b = append(e.b, 0xf6) }

// mapStart begins an indefinite-length map, which end closes.
func (e *cbor) mapStart() { e.b = append(e.b, 0xbf) }
func (e *cbor) end()      { e.b = append(e.b, 0xff) }
