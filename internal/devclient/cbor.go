//go:build dev

package devclient

import "errors"

// A minimal CBOR decoder (RFC 8949), enough to read the attestation
// documents devfake produces. Dev only. Defending against malicious CBOR is
// the job of the login page, which verifies real documents, not of this test helper.

var errCBOR = errors.New("cbor: malformed")

// Tag is a tagged item.
type Tag struct {
	Number  uint64
	Content any
}

// Decode decodes exactly one item.
func Decode(b []byte) (any, error) {
	d := decoder{b: b}
	v, err := d.item()
	if err != nil || d.off != len(d.b) {
		return nil, errCBOR
	}
	return v, nil
}

type decoder struct {
	b   []byte
	off int
}

func (d *decoder) take(n uint64) ([]byte, error) {
	if n > uint64(len(d.b)-d.off) {
		return nil, errCBOR
	}
	s := d.b[d.off : d.off+int(n)]
	d.off += int(n)
	return s, nil
}

func (d *decoder) item() (any, error) {
	head, err := d.take(1)
	if err != nil {
		return nil, err
	}
	major, ai := head[0]>>5, head[0]&0x1f
	if head[0] == 0xf6 {
		return nil, nil // null
	}
	var n uint64
	switch {
	case ai < 24:
		n = uint64(ai)
	case ai <= 27:
		p, err := d.take(1 << (ai - 24))
		if err != nil {
			return nil, err
		}
		for _, c := range p {
			n = n<<8 | uint64(c)
		}
	default:
		return nil, errCBOR // indefinite lengths are not used
	}
	switch major {
	case 0:
		return n, nil
	case 1:
		return -1 - int64(n), nil
	case 2:
		s, err := d.take(n)
		return append([]byte(nil), s...), err
	case 3:
		s, err := d.take(n)
		return string(s), err
	case 4:
		out := make([]any, 0, min(n, 64))
		for range n {
			v, err := d.item()
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		out := map[any]any{}
		for range n {
			k, err := d.item()
			if err != nil {
				return nil, err
			}
			v, err := d.item()
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	case 6:
		v, err := d.item()
		return Tag{Number: n, Content: v}, err
	}
	return nil, errCBOR
}
