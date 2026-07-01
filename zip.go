package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const (
	zipEOCDSignature            uint32 = 0x06054b50
	zipEOCDMinSize                     = 22
	zipMaxCommentSize                  = 65535
	apkSignatureSchemeV2BlockID        = 0x7109871a
)

var apkSigningBlockMagic = []byte{
	0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20,
	0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32,
}

type zipInfo struct {
	EOCDOffset       uint64
	CentralDirOffset uint64
	CentralDirSize   uint64
}

type signingBlockInfo struct {
	Offset uint64
	Size   uint64
	Block  []byte
}

type signingBlockPair struct {
	ID    uint32
	Value []byte
}

func inspectZip(data []byte) (zipInfo, error) {
	eocdOffset, err := findEOCD(data)
	if err != nil {
		return zipInfo{}, err
	}
	eocd := data[eocdOffset:]
	diskNumber := binary.LittleEndian.Uint16(eocd[4:6])
	centralDirDisk := binary.LittleEndian.Uint16(eocd[6:8])
	entriesOnDisk := binary.LittleEndian.Uint16(eocd[8:10])
	entriesTotal := binary.LittleEndian.Uint16(eocd[10:12])
	centralDirSize32 := binary.LittleEndian.Uint32(eocd[12:16])
	centralDirOffset32 := binary.LittleEndian.Uint32(eocd[16:20])

	if diskNumber != 0 || centralDirDisk != 0 {
		return zipInfo{}, errors.New("multi-disk ZIP archives are not supported")
	}
	if entriesOnDisk == math.MaxUint16 || entriesTotal == math.MaxUint16 ||
		centralDirSize32 == math.MaxUint32 || centralDirOffset32 == math.MaxUint32 {
		return zipInfo{}, errors.New("ZIP64 archives are not supported")
	}

	info := zipInfo{
		EOCDOffset:       uint64(eocdOffset),
		CentralDirOffset: uint64(centralDirOffset32),
		CentralDirSize:   uint64(centralDirSize32),
	}
	if info.CentralDirOffset > info.EOCDOffset {
		return zipInfo{}, fmt.Errorf("central directory offset %d is after EOCD %d", info.CentralDirOffset, info.EOCDOffset)
	}
	if info.CentralDirOffset+info.CentralDirSize != info.EOCDOffset {
		return zipInfo{}, fmt.Errorf("central directory size/offset do not end at EOCD: offset=%d size=%d eocd=%d", info.CentralDirOffset, info.CentralDirSize, info.EOCDOffset)
	}
	return info, nil
}

func findEOCD(data []byte) (int, error) {
	if len(data) < zipEOCDMinSize {
		return 0, errors.New("file is too small to be a ZIP archive")
	}

	minOffset := len(data) - zipEOCDMinSize - zipMaxCommentSize
	if minOffset < 0 {
		minOffset = 0
	}
	for offset := len(data) - zipEOCDMinSize; offset >= minOffset; offset-- {
		if binary.LittleEndian.Uint32(data[offset:offset+4]) == zipEOCDSignature {
			commentSize := int(binary.LittleEndian.Uint16(data[offset+20 : offset+22]))
			if offset+zipEOCDMinSize+commentSize == len(data) {
				return offset, nil
			}
		}
		if offset == 0 {
			break
		}
	}
	return 0, errors.New("ZIP End of Central Directory record not found")
}

func findSigningBlock(data []byte, centralDirOffset uint64) (signingBlockInfo, bool, error) {
	if centralDirOffset < 32 {
		return signingBlockInfo{}, false, nil
	}
	if centralDirOffset > uint64(len(data)) {
		return signingBlockInfo{}, false, fmt.Errorf("central directory offset %d exceeds file size %d", centralDirOffset, len(data))
	}

	footerOffset := centralDirOffset - 24
	footer := data[footerOffset:centralDirOffset]
	if !bytes.Equal(footer[8:24], apkSigningBlockMagic) {
		return signingBlockInfo{}, false, nil
	}

	blockSize := binary.LittleEndian.Uint64(footer[:8])
	if blockSize < 24 {
		return signingBlockInfo{}, false, fmt.Errorf("APK Signing Block size is too small: %d", blockSize)
	}
	totalSize := blockSize + 8
	if totalSize < blockSize || totalSize > centralDirOffset {
		return signingBlockInfo{}, false, fmt.Errorf("APK Signing Block size %d exceeds central directory offset %d", totalSize, centralDirOffset)
	}

	blockOffset := centralDirOffset - totalSize
	if blockOffset > uint64(len(data)) || centralDirOffset > uint64(len(data)) {
		return signingBlockInfo{}, false, errors.New("APK Signing Block range is outside file")
	}
	block := data[blockOffset:centralDirOffset]
	headerSize := binary.LittleEndian.Uint64(block[:8])
	if headerSize != blockSize {
		return signingBlockInfo{}, false, fmt.Errorf("APK Signing Block size fields differ: header=%d footer=%d", headerSize, blockSize)
	}

	return signingBlockInfo{Offset: blockOffset, Size: totalSize, Block: block}, true, nil
}

func parseSigningBlockPairs(block []byte) ([]signingBlockPair, error) {
	if len(block) < 32 {
		return nil, errors.New("APK Signing Block is too small")
	}
	pairsEnd := len(block) - 24
	offset := 8
	var pairs []signingBlockPair
	for offset < pairsEnd {
		if pairsEnd-offset < 12 {
			return nil, fmt.Errorf("truncated APK Signing Block pair at offset %d", offset)
		}
		pairSize := binary.LittleEndian.Uint64(block[offset : offset+8])
		if pairSize < 4 {
			return nil, fmt.Errorf("APK Signing Block pair size is too small: %d", pairSize)
		}
		remainingPairBytes := pairsEnd - offset - 8
		if pairSize > uint64(remainingPairBytes) {
			return nil, fmt.Errorf("APK Signing Block pair size exceeds block: %d", pairSize)
		}
		pairEnd := offset + 8 + int(pairSize)
		id := binary.LittleEndian.Uint32(block[offset+8 : offset+12])
		value := block[offset+12 : pairEnd]
		pairs = append(pairs, signingBlockPair{ID: id, Value: value})
		offset = pairEnd
	}
	if offset != pairsEnd {
		return nil, errors.New("APK Signing Block pairs are not aligned")
	}
	return pairs, nil
}

func findV2Block(block []byte) ([]byte, error) {
	pairs, err := parseSigningBlockPairs(block)
	if err != nil {
		return nil, err
	}
	var value []byte
	found := false
	for _, pair := range pairs {
		if pair.ID != apkSignatureSchemeV2BlockID {
			continue
		}
		if found {
			return nil, errors.New("duplicate APK Signature Scheme v2 blocks")
		}
		found = true
		value = pair.Value
	}
	if !found {
		return nil, errors.New("APK Signature Scheme v2 block not found")
	}
	return value, nil
}

func buildSigningBlock(v2Block []byte) []byte {
	pairSize := 4 + len(v2Block)
	totalSize := 8 + 8 + pairSize + 8 + len(apkSigningBlockMagic)
	blockSizeField := uint64(totalSize - 8)

	out := make([]byte, 0, totalSize)
	out = binary.LittleEndian.AppendUint64(out, blockSizeField)
	out = binary.LittleEndian.AppendUint64(out, uint64(pairSize))
	out = binary.LittleEndian.AppendUint32(out, apkSignatureSchemeV2BlockID)
	out = append(out, v2Block...)
	out = binary.LittleEndian.AppendUint64(out, blockSizeField)
	out = append(out, apkSigningBlockMagic...)
	return out
}

func setEOCDCentralDirectoryOffset(eocd []byte, offset uint64) error {
	if len(eocd) < zipEOCDMinSize {
		return errors.New("EOCD is too small")
	}
	if offset > math.MaxUint32 {
		return fmt.Errorf("central directory offset exceeds ZIP32 limit: %d", offset)
	}
	binary.LittleEndian.PutUint32(eocd[16:20], uint32(offset))
	return nil
}
