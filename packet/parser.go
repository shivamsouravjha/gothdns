package packet

import (
	"encoding/binary"
	"errors"
	"github.com/miekg/dns"
)

var ErrQuestionNotFound = errors.New("unable to find the question byte in the packet")
var ErrMultipleQuestionFound = errors.New("multiple questions have been found in the packet")

type PacketParser struct {
	b []byte
}

func NewPacketParser(b []byte) (*PacketParser, error) {
	return &PacketParser{
		b: b,
	}, nil
}

type PacketSlice struct {
	start uint64
	end   uint64
}

func NewMessageParser(m *dns.Msg) (*PacketParser, error) {
	b, err := m.Pack()
	if err != nil {
		return nil, errors.New("failed to pack message: " + err.Error())
	}

	return &PacketParser{
		b: b,
	}, nil
}

func (pp *PacketParser) Read(ps PacketSlice) ([]byte, error) {
	if uint64(len(pp.b)) < ps.end {
		return nil, errors.New("packet too small")
	}

	return pp.b[ps.start:ps.end], nil
}

func (pp *PacketParser) QDCOUNT() (uint16, error) {
	if len(pp.b) < 6 {
		return 0, errors.New("packet is too small to have QDCOUNT flag")
	}

	return binary.BigEndian.Uint16(pp.b[4:6]), nil
}

func (pp *PacketParser) ANCOUNT() (uint16, error) {
	if len(pp.b) < 8 {
		return 0, errors.New("packet is too small to have ANCOUNT flag")
	}

	return binary.BigEndian.Uint16(pp.b[6:8]), nil
}

func (pp *PacketParser) Header() ([]byte, error) {
	/*
	 *	Header is 12 bytes:
	 *
	 *	  0                    7  0                    7
	 *	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 *	| 					ID 							|
	 *	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 *	|QR| Opcode     |AA|TC|RD|RA| Z | RCODE 		|
	 *	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 *	| 					QDCOUNT 					|
	 *	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 *	| 					ANCOUNT 					|
	 *	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 *	| 					NSCOUNT 					|
	 *	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 *	| 					ARCOUNT 					|
	 *	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 */
	if len(pp.b) < 12 {
		return nil, errors.New("packet is too small to have an header")
	}

	return pp.b[:12], nil
}

func (pp *PacketParser) Question() (PacketSlice, error) {
	/*
	 *	  0                    7  0                    7
	 *	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 *	| 												|
	 *	/ 						QNAME 					/
	 *	/ 												/
	 *	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 *	|						QTYPE 					|
	 *	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 *	| 						QCLASS					|
	 *	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 */
	qc, err := pp.QDCOUNT()
	if err != nil {
		return PacketSlice{}, errors.New("failed to get question count: " + err.Error())
	}
	if qc > 1 {
		return PacketSlice{}, errors.New("multiple questions are not supported")
	}

	pos := 12
	for {
		if pos >= len(pp.b) {
			return PacketSlice{}, ErrQuestionNotFound
		}
		ln := int(pp.b[pos])
		if ln == 0 {
			break
		}
		pos += ln + 1
	}
	pos += 4 // QTYPE + QCLASS

	ps := PacketSlice{
		start: 12,
		end:   uint64(pos + 1),
	}

	return ps, nil
}

func (pp *PacketParser) Answer() (PacketSlice, error) {
	ac, err := pp.ANCOUNT()
	if err != nil {
		return PacketSlice{}, errors.New("failed to get answer count: " + err.Error())
	}

	qps, err := pp.Question()
	if err != nil {
		return PacketSlice{}, err
	}

	findEnd := func(pos uint64) (uint64, error) {
		for {
			if pos >= uint64(len(pp.b)) {
				return 9, ErrQuestionNotFound
			}
			ln := uint64(pp.b[pos])
			pos += ln + 1
			if ln == 0 {
				break
			}
		}
		pos += 4 // TYPE + CLASS
		pos += 4 // TTL

		rdlen := binary.BigEndian.Uint16(pp.b[pos : pos+2])
		pos += 2 + uint64(rdlen)

		return pos, nil
	}

	pos := qps.end
	for i := 0; i < int(ac); i++ {
		pos, err = findEnd(pos)
		if err != nil {
			return PacketSlice{}, err
		}
	}

	return PacketSlice{
		start: qps.end,
		end:   pos,
	}, nil
}
