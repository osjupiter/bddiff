package main

import (
	"bytes"
	"context"
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
	blockSize := int64(1024)
	totalSize := int64(1024 * 100)
	workers := 4
	ctx := context.Background()

	// Create original file
	origPath := filepath.Join(dir, "orig.bin")
	origData := make([]byte, totalSize)
	rand.Read(origData)
	os.WriteFile(origPath, origData, 0644)

	// Generate digest
	digestPath := filepath.Join(dir, "orig.digest")
	blocks, getSize := readBlocksFromFile(ctx, origPath, blockSize, workers)
	results := processBlocks(ctx, blocks, workers, nil)
	fileSize := getSize()
	if fileSize != totalSize {
		t.Fatalf("fileSize=%d, want %d", fileSize, totalSize)
	}
	writeDigest(toDigestBlocks(results), blockSize, origPath, digestPath)

	// Verify digest JSON
	digestData, _ := os.ReadFile(digestPath)
	var df DigestFile
	if err := json.Unmarshal(digestData, &df); err != nil {
		t.Fatalf("digest is not valid JSON: %v", err)
	}
	if len(df.Blocks) != int(totalSize/blockSize) {
		t.Fatalf("digest has %d blocks, want %d", len(df.Blocks), totalSize/blockSize)
	}

	// Create modified file: overwrite 10 blocks
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

	// Diff
	patchPath := filepath.Join(dir, "patch.bin")
	_, oldDigest, _ := loadDigest(digestPath)

	pf, _ := os.Create(patchPath)
	pw := newPatchWriter(pf, blockSize)
	opts := newDiffOpts(oldDigest, pw, workers)

	blocks2, getSize2 := readBlocksFromFile(ctx, modPath, blockSize, workers)
	results2 := processBlocks(ctx, blocks2, workers, opts)
	if getSize2() != totalSize {
		t.Fatalf("modified fileSize mismatch")
	}
	pw.finalize()
	pf.Close()

	if opts.changed != 10 {
		t.Fatalf("changed=%d, want 10", opts.changed)
	}

	writeDigest(toDigestBlocks(results2), blockSize, modPath, filepath.Join(dir, "mod.digest"))

	// Apply
	appliedPath := filepath.Join(dir, "applied.bin")
	os.WriteFile(appliedPath, origData, 0644)
	applyPatchForTest(t, patchPath, appliedPath)

	appliedResult, _ := os.ReadFile(appliedPath)
	if !bytes.Equal(appliedResult, modData) {
		t.Fatal("applied file does not match modified file")
	}
}

func TestRoundtripStdin(t *testing.T) {
	dir := t.TempDir()
	blockSize := int64(1024)
	totalSize := int64(1024 * 50)
	workers := 4
	ctx := context.Background()

	origData := make([]byte, totalSize)
	rand.Read(origData)
	origPath := filepath.Join(dir, "orig.bin")
	os.WriteFile(origPath, origData, 0644)

	// Digest via file
	digestPath := filepath.Join(dir, "orig.digest")
	blocks, getSize := readBlocksFromFile(ctx, origPath, blockSize, workers)
	results := processBlocks(ctx, blocks, workers, nil)
	getSize()
	writeDigest(toDigestBlocks(results), blockSize, origPath, digestPath)

	// Digest via stdin
	stdinDigestPath := filepath.Join(dir, "stdin.digest")
	blocksCh, sizeDone := readBlocksFromStream(ctx, bytes.NewReader(origData), blockSize)
	stdinResults := processBlocks(ctx, blocksCh, workers, nil)
	stdinSize := sizeDone()
	if stdinSize != totalSize {
		t.Fatalf("stdin size=%d, want %d", stdinSize, totalSize)
	}
	writeDigest(toDigestBlocks(stdinResults), blockSize, "-", stdinDigestPath)

	// Compare
	d1, _ := os.ReadFile(digestPath)
	d2, _ := os.ReadFile(stdinDigestPath)
	var df1, df2 DigestFile
	json.Unmarshal(d1, &df1)
	json.Unmarshal(d2, &df2)
	if len(df1.Blocks) != len(df2.Blocks) {
		t.Fatalf("block count mismatch")
	}
	for i := range df1.Blocks {
		if df1.Blocks[i].Hash != df2.Blocks[i].Hash {
			t.Errorf("block %d hash mismatch", i)
		}
	}
}

func TestStdinDiffRoundtrip(t *testing.T) {
	dir := t.TempDir()
	blockSize := int64(1024)
	totalSize := int64(1024 * 50)
	workers := 4
	ctx := context.Background()

	// Create original and digest
	origData := make([]byte, totalSize)
	rand.Read(origData)
	origPath := filepath.Join(dir, "orig.bin")
	os.WriteFile(origPath, origData, 0644)

	digestPath := filepath.Join(dir, "orig.digest")
	blocks, _ := readBlocksFromFile(ctx, origPath, blockSize, workers)
	results := processBlocks(ctx, blocks, workers, nil)
	writeDigest(toDigestBlocks(results), blockSize, origPath, digestPath)

	// Modified data
	modData := make([]byte, totalSize)
	copy(modData, origData)
	for _, i := range []int{5, 10, 20, 30, 40} {
		offset := int64(i) * blockSize
		rand.Read(modData[offset : offset+blockSize])
	}

	_, oldDigest, _ := loadDigest(digestPath)

	// Diff via stdin
	patchPath := filepath.Join(dir, "stdin.patch")
	pf, _ := os.Create(patchPath)
	pw := newPatchWriter(pf, blockSize)
	opts := newDiffOpts(oldDigest, pw, workers)

	stdinBlocks, _ := readBlocksFromStream(ctx, bytes.NewReader(modData), blockSize)
	processBlocks(ctx, stdinBlocks, workers, opts)
	pw.finalize()
	pf.Close()

	if opts.changed != 5 {
		t.Fatalf("changed=%d, want 5", opts.changed)
	}

	// Apply and verify
	appliedPath := filepath.Join(dir, "applied.bin")
	os.WriteFile(appliedPath, origData, 0644)
	applyPatchForTest(t, patchPath, appliedPath)

	appliedResult, _ := os.ReadFile(appliedPath)
	if !bytes.Equal(appliedResult, modData) {
		t.Fatal("stdin diff: applied file does not match")
	}
}

func TestPatchFormat(t *testing.T) {
	dir := t.TempDir()
	patchPath := filepath.Join(dir, "test.patch")

	f, _ := os.Create(patchPath)
	pw := newPatchWriter(f, 4096)
	pw.writeEntry(0, []byte("hello"))
	pw.writeEntry(4096, []byte("world"))
	pw.finalize()
	f.Close()

	pf, _ := os.Open(patchPath)
	defer pf.Close()

	header := readPatchHeader(pf)
	if header.Version != 1 {
		t.Errorf("version=%d, want 1", header.Version)
	}
	if header.BlockSize != 4096 {
		t.Errorf("blockSize=%d, want 4096", header.BlockSize)
	}
	if header.Count != 2 {
		t.Errorf("count=%d, want 2", header.Count)
	}
}

func applyPatchForTest(t *testing.T, patchPath, targetPath string) {
	t.Helper()
	pf, err := os.Open(patchPath)
	if err != nil {
		t.Fatalf("open patch: %v", err)
	}
	defer pf.Close()

	header := readPatchHeader(pf)
	tf, _ := os.OpenFile(targetPath, os.O_WRONLY, 0)
	defer tf.Close()

	for i := 0; i < header.Count; i++ {
		var offset uint64
		binary.Read(pf, binary.LittleEndian, &offset)
		var size uint32
		binary.Read(pf, binary.LittleEndian, &size)
		data := make([]byte, size)
		io.ReadFull(pf, data)
		tf.WriteAt(data, int64(offset))
	}
}
