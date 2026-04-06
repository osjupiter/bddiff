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

// --- data types ---

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

type PatchHeader struct {
	Version   int   `json:"version"`
	BlockSize int64 `json:"blockSize"`
	Count     int   `json:"count"`
}

type BlockResult struct {
	Index  int64
	Offset int64
	Hash   string
}

// --- block reader abstraction ---

// blockReader yields (index, offset, data) for each block in the source.
// file mode: each worker opens its own fd and uses ReadAt (parallel I/O).
// stdin mode: main goroutine reads sequentially, dispatches to workers.
type blockReader struct {
	blockSize int64
	workers   int
}

func (br *blockReader) hashAll(path string, r io.Reader) ([]BlockResult, int64) {
	if r != nil {
		return br.hashStream(r)
	}
	return br.hashFile(path)
}

func (br *blockReader) hashFile(path string) ([]BlockResult, int64) {
	fi, err := os.Stat(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fileSize := fi.Size()
	totalBlocks := (fileSize + br.blockSize - 1) / br.blockSize

	type job struct{ index, offset, size int64 }
	jobs := make(chan job, br.workers*2)
	results := make([]BlockResult, totalBlocks)
	var wg sync.WaitGroup

	for w := 0; w < br.workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, err := os.Open(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "worker open error: %v\n", err)
				return
			}
			defer f.Close()
			buf := make([]byte, br.blockSize)
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
		offset := i * br.blockSize
		size := br.blockSize
		if offset+size > fileSize {
			size = fileSize - offset
		}
		jobs <- job{i, offset, size}
	}
	close(jobs)
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Index < results[j].Index })
	return results, fileSize
}

func (br *blockReader) hashStream(r io.Reader) ([]BlockResult, int64) {
	type hashJob struct {
		index  int64
		offset int64
		data   []byte
	}

	jobsCh := make(chan hashJob, br.workers)
	resultsCh := make(chan BlockResult, br.workers)

	var wg sync.WaitGroup
	for w := 0; w < br.workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobsCh {
				h := md5.Sum(j.data)
				resultsCh <- BlockResult{
					Index:  j.index,
					Offset: j.offset,
					Hash:   hex.EncodeToString(h[:]),
				}
			}
		}()
	}

	var collected []BlockResult
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
		buf := make([]byte, br.blockSize)
		n, err := io.ReadFull(r, buf)
		if n == 0 {
			break
		}
		fileSize += int64(n)
		jobsCh <- hashJob{index: index, offset: index * br.blockSize, data: buf[:n]}
		if err != nil {
			break
		}
	}
	close(jobsCh)
	wg.Wait()
	close(resultsCh)
	collectorWg.Wait()

	sort.Slice(collected, func(i, j int) bool { return collected[i].Index < collected[j].Index })
	return collected, fileSize
}

// --- diff logic ---

func findChangedBlocks(results []BlockResult, oldDigest map[int64]string) []BlockResult {
	var changed []BlockResult
	for _, r := range results {
		if oldHash, ok := oldDigest[r.Offset]; !ok || oldHash != r.Hash {
			changed = append(changed, r)
		}
	}
	return changed
}

func writeChangedBlocksFromFile(path string, blockSize int64, fileSize int64, changed []BlockResult, pw *patchWriter) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening file for patch: %v\n", err)
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

func writeChangedBlocksFromStdin(r io.Reader, blockSize int64, workers int, changed []BlockResult, pw *patchWriter) {
	// For stdin diff, we need a second pass — but stdin can't be re-read.
	// Instead, the caller should use hashStreamWithDiff which captures data inline.
	// This function exists only for the file path.
	panic("writeChangedBlocksFromStdin should not be called; use hashStreamWithDiff")
}

// hashStreamWithDiff hashes stdin and writes changed blocks to patch in one pass.
func (br *blockReader) hashStreamWithDiff(r io.Reader, oldDigest map[int64]string, pw *patchWriter) ([]BlockResult, int64, int) {
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

	jobsCh := make(chan hashJob, br.workers)
	resultsCh := make(chan hashResult, br.workers)

	var wg sync.WaitGroup
	for w := 0; w < br.workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobsCh {
				h := md5.Sum(j.data)
				hash := hex.EncodeToString(h[:])
				oldHash, ok := oldDigest[j.offset]
				changed := !ok || oldHash != hash
				res := hashResult{
					BlockResult: BlockResult{Index: j.index, Offset: j.offset, Hash: hash},
					changed:     changed,
				}
				if changed {
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
		buf := make([]byte, br.blockSize)
		n, err := io.ReadFull(r, buf)
		if n == 0 {
			break
		}
		fileSize += int64(n)
		jobsCh <- hashJob{index: index, offset: index * br.blockSize, data: buf[:n]}
		if err != nil {
			break
		}
	}
	close(jobsCh)
	wg.Wait()
	close(resultsCh)
	collectorWg.Wait()

	sort.Slice(collected, func(i, j int) bool { return collected[i].Index < collected[j].Index })

	changedCount := 0
	results := make([]BlockResult, len(collected))
	for i, c := range collected {
		results[i] = c.BlockResult
		if c.changed {
			changedCount++
			pw.writeEntry(c.Offset, c.data)
		}
	}
	return results, fileSize, changedCount
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

type patchWriter struct {
	f         *os.File
	blockSize int64
	headerPos int64
}

func newPatchWriter(f *os.File, blockSize int64) *patchWriter {
	f.Write([]byte(patchMagic))
	headerPos, _ := f.Seek(0, io.SeekCurrent)
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
	header := PatchHeader{Version: 1, BlockSize: pw.blockSize, Count: count}
	headerJSON, _ := json.Marshal(header)
	padded := make([]byte, 256)
	copy(padded, headerJSON)
	pw.f.Seek(pw.headerPos, io.SeekStart)
	binary.Write(pw.f, binary.LittleEndian, uint32(len(headerJSON)))
	pw.f.Write(padded)
}

// --- commands ---

var rootCmd = &cobra.Command{
	Use:   "bddiff",
	Short: "Parallel block-level MD5 digest and binary diff tool",
}

// digest

var (
	digestBS      int64
	digestWorkers int
	digestOut     string
)

var digestCmd = &cobra.Command{
	Use:   "digest <file | ->",
	Short: "Generate block-level MD5 digest",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		path := args[0]
		br := &blockReader{blockSize: digestBS, workers: digestWorkers}
		start := time.Now()

		var results []BlockResult
		var fileSize int64
		if path == "-" {
			results, fileSize = br.hashAll("", os.Stdin)
		} else {
			results, fileSize = br.hashAll(path, nil)
		}

		writeDigest(results, digestBS, path, digestOut)
		printStats(path, fileSize, digestBS, len(results), digestWorkers, start)
	},
}

// diff

var (
	diffBS      int64
	diffWorkers int
	diffOut     string
	diffDigest  string
	diffPatch   string
)

var diffCmd = &cobra.Command{
	Use:   "diff <file | ->",
	Short: "Generate new digest and binary patch from old digest",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		path := args[0]

		oldBS, oldDigest, err := loadDigest(diffDigest)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading digest: %v\n", err)
			os.Exit(1)
		}
		if oldBS > 0 && oldBS != diffBS {
			fmt.Fprintf(os.Stderr, "using block size %d from digest file\n", oldBS)
			diffBS = oldBS
		}

		patchFile, err := os.Create(diffPatch)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating patch file: %v\n", err)
			os.Exit(1)
		}
		defer patchFile.Close()
		pw := newPatchWriter(patchFile, diffBS)

		br := &blockReader{blockSize: diffBS, workers: diffWorkers}
		start := time.Now()

		var results []BlockResult
		var fileSize int64
		var changedCount int

		if path == "-" {
			// stdin: one-pass hash + diff + patch (can't re-read)
			results, fileSize, changedCount = br.hashStreamWithDiff(os.Stdin, oldDigest, pw)
		} else {
			// file: hash all, then read only changed blocks for patch
			results, fileSize = br.hashAll(path, nil)
			changed := findChangedBlocks(results, oldDigest)
			changedCount = len(changed)
			writeChangedBlocksFromFile(path, diffBS, fileSize, changed, pw)
		}

		pw.finalize(changedCount)
		writeDigest(results, diffBS, path, diffOut)

		printStats(path, fileSize, diffBS, len(results), diffWorkers, start)
		fmt.Fprintf(os.Stderr, "changed blocks: %d / %d (%.1f%%)\n",
			changedCount, len(results), float64(changedCount)/float64(len(results))*100)
	},
}

// apply

var applyCmd = &cobra.Command{
	Use:   "apply <patch> <file>",
	Short: "Apply a binary patch to a file",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		patchPath := args[0]
		targetPath := args[1]

		pf, err := os.Open(patchPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error opening patch: %v\n", err)
			os.Exit(1)
		}
		defer pf.Close()

		magic := make([]byte, len(patchMagic))
		if _, err := io.ReadFull(pf, magic); err != nil || string(magic) != patchMagic {
			fmt.Fprintf(os.Stderr, "error: not a valid patch file (bad magic)\n")
			os.Exit(1)
		}

		var headerSize uint32
		binary.Read(pf, binary.LittleEndian, &headerSize)
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

		fmt.Fprintf(os.Stderr, "patch: version=%d, blockSize=%d, blocks=%d\n",
			header.Version, header.BlockSize, header.Count)

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
		fmt.Fprintf(os.Stderr, "applied %d blocks (%.1f MB) to %s\n",
			applied, float64(totalBytes)/1024/1024, targetPath)
	},
}

func init() {
	digestCmd.Flags().Int64VarP(&digestBS, "block-size", "b", 1048576, "block size in bytes")
	digestCmd.Flags().IntVarP(&digestWorkers, "jobs", "j", runtime.NumCPU(), "number of parallel workers")
	digestCmd.Flags().StringVarP(&digestOut, "output", "o", "", "output digest file (default: stdout)")

	diffCmd.Flags().Int64VarP(&diffBS, "block-size", "b", 1048576, "block size in bytes")
	diffCmd.Flags().IntVarP(&diffWorkers, "jobs", "j", runtime.NumCPU(), "number of parallel workers")
	diffCmd.Flags().StringVarP(&diffOut, "output", "o", "", "output digest file (default: stdout)")
	diffCmd.Flags().StringVarP(&diffDigest, "digest", "d", "", "old digest file (required)")
	diffCmd.Flags().StringVarP(&diffPatch, "patch", "p", "", "output patch file (required)")
	diffCmd.MarkFlagRequired("digest")
	diffCmd.MarkFlagRequired("patch")

	rootCmd.AddCommand(digestCmd)
	rootCmd.AddCommand(diffCmd)
	rootCmd.AddCommand(applyCmd)
}

// --- util ---

func printStats(path string, fileSize int64, blockSize int64, totalBlocks int, workers int, start time.Time) {
	elapsed := time.Since(start)
	throughput := float64(fileSize) / elapsed.Seconds() / 1024 / 1024
	fmt.Fprintf(os.Stderr, "file: %s (%d bytes)\n", path, fileSize)
	fmt.Fprintf(os.Stderr, "block size: %d, total blocks: %d, workers: %d\n", blockSize, totalBlocks, workers)
	fmt.Fprintf(os.Stderr, "done in %.2fs (%.0f MB/s)\n", elapsed.Seconds(), throughput)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
