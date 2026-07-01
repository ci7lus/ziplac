package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type intBytesPair struct {
	ID    uint32
	Value []byte
}

func encodeLengthPrefixed(value []byte) []byte {
	out := make([]byte, 4+len(value))
	binary.LittleEndian.PutUint32(out[:4], uint32(len(value)))
	copy(out[4:], value)
	return out
}

func encodeSequence(elements [][]byte) []byte {
	total := 0
	for _, element := range elements {
		total += 4 + len(element)
	}
	out := make([]byte, 0, total)
	for _, element := range elements {
		out = append(out, encodeLengthPrefixed(element)...)
	}
	return out
}

func encodeIntBytesPairs(pairs []intBytesPair) []byte {
	elements := make([][]byte, 0, len(pairs))
	for _, pair := range pairs {
		record := make([]byte, 4, 8+len(pair.Value))
		binary.LittleEndian.PutUint32(record, pair.ID)
		record = append(record, encodeLengthPrefixed(pair.Value)...)
		elements = append(elements, record)
	}
	return encodeSequence(elements)
}

type byteReader struct {
	data []byte
	pos  int
}

func newByteReader(data []byte) *byteReader {
	return &byteReader{data: data}
}

func (r *byteReader) remaining() int {
	return len(r.data) - r.pos
}

func (r *byteReader) hasRemaining() bool {
	return r.remaining() > 0
}

func (r *byteReader) readUint32() (uint32, error) {
	if r.remaining() < 4 {
		return 0, errors.New("truncated uint32")
	}
	value := binary.LittleEndian.Uint32(r.data[r.pos : r.pos+4])
	r.pos += 4
	return value, nil
}

func (r *byteReader) readLengthPrefixedBytes() ([]byte, error) {
	size, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	if size > uint32(r.remaining()) {
		return nil, fmt.Errorf("length-prefixed field exceeds remaining data: size=%d remaining=%d", size, r.remaining())
	}
	value := r.data[r.pos : r.pos+int(size)]
	r.pos += int(size)
	return value, nil
}

func parseIntBytesPairs(data []byte) ([]intBytesPair, error) {
	reader := newByteReader(data)
	var pairs []intBytesPair
	for reader.hasRemaining() {
		record, err := reader.readLengthPrefixedBytes()
		if err != nil {
			return nil, err
		}
		recordReader := newByteReader(record)
		id, err := recordReader.readUint32()
		if err != nil {
			return nil, err
		}
		value, err := recordReader.readLengthPrefixedBytes()
		if err != nil {
			return nil, err
		}
		if recordReader.hasRemaining() {
			return nil, fmt.Errorf("unexpected trailing bytes in ID/value record: %d", recordReader.remaining())
		}
		pairs = append(pairs, intBytesPair{ID: id, Value: value})
	}
	return pairs, nil
}
