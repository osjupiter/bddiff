package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRoundtrip(t *testing.T) {
	dir := t.TempDir()
	blockSize := int64(1024) // 1KB blocks for fast test
	totalSize := int64(1024 * 100) // 100KB
	workers := 4

	// Create original file with random data
	origPath := filepath.Join(dir, "orig.bin")
	origData := make([]byte, totalSize)
	rand.Read(origData)
	os.WriteFile(origPath, origData, 0644)

	// Generate digest
	digestPath := filepath.Join(dir, "orig.digest")
	blocks, getSize := readBlocks(origPath, blockSize, workers)
	results := hashBlocks(blocks, workers, false)
	fileSize := getSize()
	if fileSize != totalSize {
		t.Fatalf("fileSize=%d, want %d", fileSize, totalSize)
	}
	writeDigest(toDigestBlocks(results), blockSize, origPath, digestPath)

	// Verify digest is valid JSON
	digestData, _ := os.ReadFile(digestPath)
	var df DigestFile
	if err := json.Unmarshal(digestData, &df); err != nil {
		t.Fatalf("digest is not valid JSON: %v", err)
	}
	expectedBlocks := int(totalSize / blockSize)
	if len(df.Blocks) != expectedBlocks {
		t.Fatalf("digest has %d blocks, want %d", len(df.Blocks), expectedBlocks)
	}

	// Create modified file: overwrite 10 random blocks
	modData := make([]byte, totalSize)
	copy(modData, origData)
	changedOffsets := map[int64]bool{}
	for _, i := range []int{3, 7, 15, 22, 41, 55, 68, 73, 88, 95} {
		offset := int64(i) * blockSize
		rand.Read(modData[offset : offset+blockSize])
		changedOffsets[offset] = true
	}
	modPath := filepath.Join(dir, "mod.bin")
	os.WriteFile(modPath, modData, 0644)

	// Diff: generate new digest + patch
	patchPath := filepath.Join(dir, "patch.bin")
	newDigestPath := filepath.Join(dir, "mod.digest")

	oldBS, oldDigest, err := loadDigest(digestPath)
	if err != nil {
		t.Fatalf("loadDigest: %v", err)
	}
	if oldBS != blockSize {
		t.Fatalf("loaded blockSize=%d, want %d", oldBS, blockSize)
	}

	pf, _ := os.Create(patchPath)
	pw := newPatchWriter(pf, blockSize)

	blocks2, getSize2 := readBlocks(modPath, blockSize, workers)
	results2 := hashBlocks(blocks2, workers, true)
	fileSize2 := getSize2()
	if fileSize2 != totalSize {
		t.Fatalf("modified fileSize=%d, want %d", fileSize2, totalSize)
	}

	changed := findChangedBlocks(results2, oldDigest)
	writePatchBlocks(changed, pw)
	pw.finalize(len(changed))
	pf.Close()

	writeDigest(toDigestBlocks(results2), blockSize, modPath, newDigestPath)

	// Verify changed block count
	if len(changed) != 10 {
		t.Fatalf("changed=%d, want 10", len(changed))
	}

	// Verify changed block offsets match
	for _, c := range changed {
		if !changedOffsets[c.offset] {
			t.Errorf("unexpected changed block at offset %d", c.offset)
		}
	}

	// Apply patch to copy of original
	appliedPath := filepath.Join(dir, "applied.bin")
	appliedData := make([]byte, totalSize)
	copy(appliedData, origData)
	os.WriteFile(appliedPath, appliedData, 0644)

	applyPatch(t, patchPath, appliedPath)

	// Verify applied file matches modified file
	appliedResult, _ := os.ReadFile(appliedPath)
	if !bytes.Equal(appliedResult, modData) {
		t.Fatal("applied file does not match modified file")
	}
}

func TestRoundtripStdin(t *testing.T) {
	dir := t.TempDir()
	blockSize := int64(1024)
	totalSize := int64(1024 * 50) // 50KB
	workers := 4

	// Create original
	origData := make([]byte, totalSize)
	rand.Read(origData)
	origPath := filepath.Join(dir, "orig.bin")
	os.WriteFile(origPath, origData, 0644)

	// Digest via file
	digestPath := filepath.Join(dir, "orig.digest")
	blocks, getSize := readBlocks(origPath, blockSize, workers)
	results := hashBlocks(blocks, workers, false)
	getSize()
	writeDigest(toDigestBlocks(results), blockSize, origPath, digestPath)

	// Digest via stdin and compare
	stdinDigestPath := filepath.Join(dir, "stdin.digest")
	stdinReader := bytes.NewReader(origData)
	blocksCh, sizeDone := readBlocksFromStream(stdinReader, blockSize)
	stdinResults := hashBlocks(blocksCh, workers, false)
	stdinSize := sizeDone()
	if stdinSize != totalSize {
		t.Fatalf("stdin size=%d, want %d", stdinSize, totalSize)
	}
	writeDigest(toDigestBlocks(stdinResults), blockSize, "-", stdinDigestPath)

	// Compare digests (ignoring file field)
	d1, _ := os.ReadFile(digestPath)
	d2, _ := os.ReadFile(stdinDigestPath)
	var df1, df2 DigestFile
	json.Unmarshal(d1, &df1)
	json.Unmarshal(d2, &df2)

	if len(df1.Blocks) != len(df2.Blocks) {
		t.Fatalf("block count mismatch: %d vs %d", len(df1.Blocks), len(df2.Blocks))
	}
	for i := range df1.Blocks {
		if df1.Blocks[i].Hash != df2.Blocks[i].Hash {
			t.Errorf("block %d hash mismatch", i)
		}
	}
}

func TestPatchFormat(t *testing.T) {
	dir := t.TempDir()
	patchPath := filepath.Join(dir, "test.patch")

	f, _ := os.Create(patchPath)
	pw := newPatchWriter(f, 4096)
	pw.writeEntry(0, []byte("hello"))
	pw.writeEntry(4096, []byte("world"))
	pw.finalize(2)
	f.Close()

	// Read back and verify
	pf, _ := os.Open(patchPath)
	defer pf.Close()

	magic := make([]byte, 8)
	io.ReadFull(pf, magic)
	if string(magic) != patchMagic {
		t.Fatalf("bad magic: %q", magic)
	}

	var headerSize uint32
	binary.Read(pf, binary.LittleEndian, &headerSize)
	paddedBuf := make([]byte, 256)
	io.ReadFull(pf, paddedBuf)

	var header PatchHeader
	json.Unmarshal(paddedBuf[:headerSize], &header)

	if header.Version != 1 {
		t.Errorf("version=%d, want 1", header.Version)
	}
	if header.BlockSize != 4096 {
		t.Errorf("blockSize=%d, want 4096", header.BlockSize)
	}
	if header.Count != 2 {
		t.Errorf("count=%d, want 2", header.Count)
	}

	// Read entries
	for _, expected := range []struct {
		offset uint64
		data   string
	}{{0, "hello"}, {4096, "world"}} {
		var offset uint64
		binary.Read(pf, binary.LittleEndian, &offset)
		var size uint32
		binary.Read(pf, binary.LittleEndian, &size)
		data := make([]byte, size)
		io.ReadFull(pf, data)

		if offset != expected.offset {
			t.Errorf("offset=%d, want %d", offset, expected.offset)
		}
		if string(data) != expected.data {
			t.Errorf("data=%q, want %q", data, expected.data)
		}
	}
}

// applyPatch applies a patch file to a target (reuses the apply logic inline for testing)
func applyPatch(t *testing.T, patchPath, targetPath string) {
	t.Helper()

	pf, err := os.Open(patchPath)
	if err != nil {
		t.Fatalf("open patch: %v", err)
	}
	defer pf.Close()

	magic := make([]byte, len(patchMagic))
	io.ReadFull(pf, magic)
	if string(magic) != patchMagic {
		t.Fatalf("bad magic")
	}

	var headerSize uint32
	binary.Read(pf, binary.LittleEndian, &headerSize)
	paddedBuf := make([]byte, 256)
	io.ReadFull(pf, paddedBuf)

	var header PatchHeader
	json.Unmarshal(paddedBuf[:headerSize], &header)

	tf, _ := os.OpenFile(targetPath, os.O_WRONLY, 0)
	defer tf.Close()

	applied := 0
	for {
		var offset uint64
		if err := binary.Read(pf, binary.LittleEndian, &offset); err != nil {
			break
		}
		var size uint32
		binary.Read(pf, binary.LittleEndian, &size)
		data := make([]byte, size)
		io.ReadFull(pf, data)
		tf.WriteAt(data, int64(offset))
		applied++
	}

	if applied != header.Count {
		t.Errorf("applied %d blocks, header says %d", applied, header.Count)
	}
}
