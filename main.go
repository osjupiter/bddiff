package main

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

const patchMagic = "BDPATCH2"

// --- digest format (JSON) ---

type DigestFile struct {
	Version   int           `json:"version"`
	Algorithm string        `json:"algorithm"`
	BlockSize int64         `json:"blockSize"`
	File      string        `json:"file"`
	Blocks    []DigestBlock `json:"blocks"`
}

type DigestBlock struct {
	Offset int64  `json:"offset"`
	Hash   string `json:"hash"`
}

// --- patch header (JSON in binary envelope) ---

type PatchHeader struct {
	Version   int   `json:"version"`
	BlockSize int64 `json:"blockSize"`
	Count     int   `json:"count"`
}

// --- internal types ---

type BlockResult struct {
	Index  int64
	Offset int64
	Hash   string
}

var rootCmd = &cobra.Command{
	Use:   "bddiff",
	Short: "Parallel block-level MD5 digest and binary diff tool",
}

// --- digest command ---

var digestCmd = &cobra.Command{
	Use:   "digest <file | ->",
	Short: "Generate block-level MD5 digest",
	Args:  cobra.ExactArgs(1),
	Run:   runDigest,
}

var (
	digestBS      int64
	digestWorkers int
	digestOut     string
)

func init() {
	digestCmd.Flags().Int64VarP(&digestBS, "block-size", "b", 1048576, "block size in bytes")
	digestCmd.Flags().IntVarP(&digestWorkers, "jobs", "j", runtime.NumCPU(), "number of parallel workers")
	digestCmd.Flags().StringVarP(&digestOut, "output", "o", "", "output digest file (default: stdout)")
	rootCmd.AddCommand(digestCmd)
}

func runDigest(cmd *cobra.Command, args []string) {
	path := args[0]
	isStdin := path == "-"
	start := time.Now()

	var results []BlockResult
	var fileSize int64

	if isStdin {
		results, fileSize, _ = processStdin(os.Stdin, digestBS, digestWorkers, nil, nil)
	} else {
		results, fileSize, _ = processFile(path, digestBS, digestWorkers, nil, nil)
	}

	writeDigest(results, digestBS, path, digestOut)

	elapsed := time.Since(start)
	throughput := float64(fileSize) / elapsed.Seconds() / 1024 / 1024
	fmt.Fprintf(os.Stderr, "file: %s (%d bytes)\n", path, fileSize)
	fmt.Fprintf(os.Stderr, "block size: %d, total blocks: %d, workers: %d\n", digestBS, len(results), digestWorkers)
	fmt.Fprintf(os.Stderr, "done in %.2fs (%.0f MB/s)\n", elapsed.Seconds(), throughput)
}

// --- diff command ---

var diffCmd = &cobra.Command{
	Use:   "diff <file | ->",
	Short: "Generate new digest and binary patch from old digest",
	Args:  cobra.ExactArgs(1),
	Run:   runDiff,
}

var (
	diffBS      int64
	diffWorkers int
	diffOut     string
	diffDigest  string
	diffPatch   string
)

func init() {
	diffCmd.Flags().Int64VarP(&diffBS, "block-size", "b", 1048576, "block size in bytes")
	diffCmd.Flags().IntVarP(&diffWorkers, "jobs", "j", runtime.NumCPU(), "number of parallel workers")
	diffCmd.Flags().StringVarP(&diffOut, "output", "o", "", "output digest file (default: stdout)")
	diffCmd.Flags().StringVarP(&diffDigest, "digest", "d", "", "old digest file (required)")
	diffCmd.Flags().StringVarP(&diffPatch, "patch", "p", "", "output patch file (required)")
	diffCmd.MarkFlagRequired("digest")
	diffCmd.MarkFlagRequired("patch")
	rootCmd.AddCommand(diffCmd)
}

func runDiff(cmd *cobra.Command, args []string) {
	path := args[0]
	isStdin := path == "-"

	oldBS, oldDigest, err := loadDigest(diffDigest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading digest: %v\n", err)
		os.Exit(1)
	}
	if oldBS > 0 && oldBS != diffBS {
		fmt.Fprintf(os.Stderr, "using block size %d from digest file\n", oldBS)
		diffBS = oldBS
	}

	// Create patch file, write magic, reserve space for header
	patchFile, err := os.Create(diffPatch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating patch file: %v\n", err)
		os.Exit(1)
	}
	defer patchFile.Close()
	pw := newPatchWriter(patchFile, diffBS)

	start := time.Now()

	var results []BlockResult
	var fileSize int64
	var changedCount int

	if isStdin {
		results, fileSize, changedCount = processStdin(os.Stdin, diffBS, diffWorkers, oldDigest, pw)
	} else {
		results, fileSize, changedCount = processFile(path, diffBS, diffWorkers, oldDigest, pw)
	}

	// Finalize patch header with actual count
	pw.finalize(changedCount)

	writeDigest(results, diffBS, path, diffOut)

	elapsed := time.Since(start)
	throughput := float64(fileSize) / elapsed.Seconds() / 1024 / 1024
	fmt.Fprintf(os.Stderr, "file: %s (%d bytes)\n", path, fileSize)
	fmt.Fprintf(os.Stderr, "block size: %d, total blocks: %d, workers: %d\n", diffBS, len(results), diffWorkers)
	fmt.Fprintf(os.Stderr, "changed blocks: %d / %d (%.1f%%)\n", changedCount, len(results), float64(changedCount)/float64(len(results))*100)
	fmt.Fprintf(os.Stderr, "done in %.2fs (%.0f MB/s)\n", elapsed.Seconds(), throughput)
}

// --- apply command ---

var applyCmd = &cobra.Command{
	Use:   "apply <patch> <file>",
	Short: "Apply a binary patch to a file",
	Args:  cobra.ExactArgs(2),
	Run:   runApply,
}

func init() {
	rootCmd.AddCommand(applyCmd)
}

func runApply(cmd *cobra.Command, args []string) {
	patchPath := args[0]
	targetPath := args[1]

	pf, err := os.Open(patchPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening patch: %v\n", err)
		os.Exit(1)
	}
	defer pf.Close()

	// Read and verify magic
	magic := make([]byte, len(patchMagic))
	if _, err := io.ReadFull(pf, magic); err != nil || string(magic) != patchMagic {
		fmt.Fprintf(os.Stderr, "error: not a valid patch file (bad magic)\n")
		os.Exit(1)
	}

	// Read header size and JSON header
	var headerSize uint32
	binary.Read(pf, binary.LittleEndian, &headerSize)

	// Read the full 256-byte padded header area, then parse only headerSize bytes
	paddedBuf := make([]byte, 256)
	if _, err := io.ReadFull(pf, paddedBuf); err != nil {
		fmt.Fprintf(os.Stderr, "error reading patch header: %v\n", err)
		os.Exit(1)
	}

	var header PatchHeader
	if err := json.Unmarshal(paddedBuf[:headerSize], &header); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing patch header: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "patch: version=%d, blockSize=%d, blocks=%d\n", header.Version, header.BlockSize, header.Count)

	// Open target
	tf, err := os.OpenFile(targetPath, os.O_WRONLY, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening target: %v\n", err)
		os.Exit(1)
	}
	defer tf.Close()

	applied := 0
	var totalBytes uint64
	for {
		var offset uint64
		if err := binary.Read(pf, binary.LittleEndian, &offset); err != nil {
			break
		}
		var size uint32
		binary.Read(pf, binary.LittleEndian, &size)

		data := make([]byte, size)
		if _, err := io.ReadFull(pf, data); err != nil {
			fmt.Fprintf(os.Stderr, "error reading patch data at offset %d: %v\n", offset, err)
			os.Exit(1)
		}

		if _, err := tf.WriteAt(data, int64(offset)); err != nil {
			fmt.Fprintf(os.Stderr, "error writing at offset %d: %v\n", offset, err)
			os.Exit(1)
		}
		applied++
		totalBytes += uint64(size)
	}

	if applied != header.Count {
		fmt.Fprintf(os.Stderr, "warning: expected %d blocks but applied %d\n", header.Count, applied)
	}
	fmt.Fprintf(os.Stderr, "applied %d blocks (%.1f MB) to %s\n", applied, float64(totalBytes)/1024/1024, targetPath)
}

// --- digest I/O ---

func loadDigest(path string) (int64, map[int64]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()

	var df DigestFile
	if err := json.NewDecoder(f).Decode(&df); err != nil {
		return 0, nil, fmt.Errorf("invalid digest JSON: %w", err)
	}

	digests := make(map[int64]string, len(df.Blocks))
	for _, b := range df.Blocks {
		digests[b.Offset] = b.Hash
	}
	return df.BlockSize, digests, nil
}

func writeDigest(results []BlockResult, blockSize int64, path string, outFile string) {
	df := DigestFile{
		Version:   1,
		Algorithm: "md5",
		BlockSize: blockSize,
		File:      path,
		Blocks:    make([]DigestBlock, len(results)),
	}
	for i, r := range results {
		df.Blocks[i] = DigestBlock{Offset: r.Offset, Hash: r.Hash}
	}

	var out io.Writer = os.Stdout
	if outFile != "" {
		f, err := os.Create(outFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		out = f
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(df); err != nil {
		fmt.Fprintf(os.Stderr, "error writing digest: %v\n", err)
		os.Exit(1)
	}
}

// --- patch I/O ---

// patchWriter handles the two-phase patch writing:
// 1. Write magic + placeholder header size + empty header space
// 2. Write entries as they come
// 3. finalize() seeks back and writes the real header with count
type patchWriter struct {
	f         *os.File
	blockSize int64
	headerPos int64 // position where header_size starts
}

func newPatchWriter(f *os.File, blockSize int64) *patchWriter {
	// Write magic
	f.Write([]byte(patchMagic))

	// Remember position, write placeholder header (size=0, empty)
	headerPos, _ := f.Seek(0, io.SeekCurrent)

	// Reserve: uint32 header_size + max header JSON space (256 bytes is plenty)
	placeholder := make([]byte, 4+256)
	f.Write(placeholder)

	return &patchWriter{f: f, blockSize: blockSize, headerPos: headerPos}
}

func (pw *patchWriter) writeEntry(offset int64, data []byte) {
	binary.Write(pw.f, binary.LittleEndian, uint64(offset))
	binary.Write(pw.f, binary.LittleEndian, uint32(len(data)))
	pw.f.Write(data)
}

func (pw *patchWriter) finalize(count int) {
	header := PatchHeader{
		Version:   1,
		BlockSize: pw.blockSize,
		Count:     count,
	}
	headerJSON, _ := json.Marshal(header)
	headerSize := uint32(len(headerJSON))

	// Pad to 256 bytes so we don't shift entry data
	padded := make([]byte, 256)
	copy(padded, headerJSON)

	// Seek back and write real header
	pw.f.Seek(pw.headerPos, io.SeekStart)
	binary.Write(pw.f, binary.LittleEndian, headerSize)
	pw.f.Write(padded)
}

// --- core logic ---

func processFile(path string, blockSize int64, workers int, oldDigest map[int64]string, pw *patchWriter) ([]BlockResult, int64, int) {
	fi, err := os.Stat(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fileSize := fi.Size()
	totalBlocks := (fileSize + blockSize - 1) / blockSize

	type job struct {
		index, offset, size int64
	}
	jobs := make(chan job, workers*2)
	results := make([]BlockResult, totalBlocks)
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, err := os.Open(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "worker open error: %v\n", err)
				return
			}
			defer f.Close()
			buf := make([]byte, blockSize)
			for j := range jobs {
				n, _ := f.ReadAt(buf[:j.size], j.offset)
				h := md5.Sum(buf[:n])
				results[j.index] = BlockResult{
					Index:  j.index,
					Offset: j.offset,
					Hash:   hex.EncodeToString(h[:]),
				}
			}
		}()
	}

	for i := int64(0); i < totalBlocks; i++ {
		offset := i * blockSize
		size := blockSize
		if offset+size > fileSize {
			size = fileSize - offset
		}
		jobs <- job{i, offset, size}
	}
	close(jobs)
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		return results[i].Index < results[j].Index
	})

	changedCount := 0
	if oldDigest != nil && pw != nil {
		var changed []BlockResult
		for _, r := range results {
			if oldHash, ok := oldDigest[r.Offset]; !ok || oldHash != r.Hash {
				changed = append(changed, r)
			}
		}
		changedCount = len(changed)

		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reopening file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		buf := make([]byte, blockSize)
		for _, r := range changed {
			size := blockSize
			if r.Offset+size > fileSize {
				size = fileSize - r.Offset
			}
			n, _ := f.ReadAt(buf[:size], r.Offset)
			pw.writeEntry(r.Offset, buf[:n])
		}
	}

	return results, fileSize, changedCount
}

func processStdin(r io.Reader, blockSize int64, workers int, oldDigest map[int64]string, pw *patchWriter) ([]BlockResult, int64, int) {
	type hashJob struct {
		index  int64
		offset int64
		data   []byte
	}
	type hashResult struct {
		BlockResult
		changed bool
		data    []byte
	}

	jobsCh := make(chan hashJob, workers)
	resultsCh := make(chan hashResult, workers)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobsCh {
				h := md5.Sum(j.data)
				hash := hex.EncodeToString(h[:])
				changed := false
				if oldDigest != nil {
					oldHash, ok := oldDigest[j.offset]
					changed = !ok || oldHash != hash
				}
				res := hashResult{
					BlockResult: BlockResult{Index: j.index, Offset: j.offset, Hash: hash},
					changed:     changed,
				}
				if changed && pw != nil {
					res.data = j.data
				}
				resultsCh <- res
			}
		}()
	}

	var collected []hashResult
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for r := range resultsCh {
			collected = append(collected, r)
		}
	}()

	var fileSize int64
	for index := int64(0); ; index++ {
		buf := make([]byte, blockSize)
		n, err := io.ReadFull(r, buf)
		if n == 0 {
			break
		}
		fileSize += int64(n)
		jobsCh <- hashJob{index: index, offset: index * blockSize, data: buf[:n]}
		if err != nil {
			break
		}
	}
	close(jobsCh)
	wg.Wait()
	close(resultsCh)
	collectorWg.Wait()

	sort.Slice(collected, func(i, j int) bool {
		return collected[i].Index < collected[j].Index
	})

	changedCount := 0
	results := make([]BlockResult, len(collected))
	for i, c := range collected {
		results[i] = c.BlockResult
		if c.changed {
			changedCount++
			if pw != nil && c.data != nil {
				pw.writeEntry(c.Offset, c.data)
			}
		}
	}

	return results, fileSize, changedCount
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
