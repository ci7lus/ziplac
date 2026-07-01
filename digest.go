package main

import (
	"crypto"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
)

const contentDigestChunkSize = 1024 * 1024

func computeContentDigest(alg contentDigestAlgorithm, sections ...[]byte) ([]byte, error) {
	hashID, digestSize, err := contentDigestHash(alg)
	if err != nil {
		return nil, err
	}
	if !hashID.Available() {
		return nil, fmt.Errorf("hash %s is not available", hashID.String())
	}

	chunkCount := uint64(0)
	for _, section := range sections {
		chunkCount += uint64((len(section) + contentDigestChunkSize - 1) / contentDigestChunkSize)
	}
	if chunkCount > math.MaxUint32 {
		return nil, fmt.Errorf("too many content chunks: %d", chunkCount)
	}

	chunkDigests := make([]byte, 0, int(chunkCount)*digestSize)
	for _, section := range sections {
		for offset := 0; offset < len(section); offset += contentDigestChunkSize {
			end := offset + contentDigestChunkSize
			if end > len(section) {
				end = len(section)
			}
			digest := digestChunk(hashID.New(), section[offset:end])
			chunkDigests = append(chunkDigests, digest...)
		}
	}

	final := hashID.New()
	var prefix [5]byte
	prefix[0] = 0x5a
	binary.LittleEndian.PutUint32(prefix[1:], uint32(chunkCount))
	_, _ = final.Write(prefix[:])
	_, _ = final.Write(chunkDigests)
	return final.Sum(nil), nil
}

func digestChunk(h hash.Hash, chunk []byte) []byte {
	var prefix [5]byte
	prefix[0] = 0xa5
	binary.LittleEndian.PutUint32(prefix[1:], uint32(len(chunk)))
	_, _ = h.Write(prefix[:])
	_, _ = h.Write(chunk)
	return h.Sum(nil)
}

func contentDigestHash(alg contentDigestAlgorithm) (crypto.Hash, int, error) {
	switch alg {
	case contentDigestChunkedSHA256:
		return crypto.SHA256, crypto.SHA256.Size(), nil
	case contentDigestChunkedSHA512:
		return crypto.SHA512, crypto.SHA512.Size(), nil
	default:
		return 0, 0, fmt.Errorf("unsupported content digest algorithm ID %d", alg)
	}
}
