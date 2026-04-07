package main

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

const patchMagic = "BDPATCH3"

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

type block struct {
	index  int64
	offset int64
	data   []byte
}

type hashResult struct {
	index  int64
	offset int64
	hash   string
}

// --- block reading ---

func readBlocks(ctx context.Context, path string, blockSize int64, workers int) (chan block, func() int64) {
	if path == "-" {
		return readBlocksFromStream(ctx, os.Stdin, blockSize)
	}
	return readBlocksFromFile(ctx, path, blockSize, workers)
}

func readBlocksFromFile(ctx context.Context, path string, blockSize int64, workers int) (chan block, func() int64) {
	fi, err := os.Stat(path)
	if err != nil {
		fatal("error: %v", err)
	}
	fileSize := fi.Size()
	totalBlocks := (fileSize + blockSize - 1) / blockSize
	ch := make(chan block, workers*2)

	type job struct{ index, offset, size int64 }
	jobs := make(chan job, workers*2)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, err := os.Open(path)
			if err != nil {
				fatal("worker open error: %v", err)
			}
			defer f.Close()
			for j := range jobs {
				buf := make([]byte, j.size)
				n, err := f.ReadAt(buf, j.offset)
				if err != nil && err != io.EOF {
					fatal("read error at offset %d: %v", j.offset, err)
				}
				ch <- block{index: j.index, offset: j.offset, data: buf[:n]}
			}
		}()
	}

	go func() {
		for i := int64(0); i < totalBlocks; i++ {
			select {
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				close(ch)
				return
			default:
			}
			offset := i * blockSize
			size := blockSize
			if offset+size > fileSize {
				size = fileSize - offset
			}
			jobs <- job{i, offset, size}
		}
		close(jobs)
		wg.Wait()
		close(ch)
	}()

	return ch, func() int64 { return fileSize }
}

func readBlocksFromStream(ctx context.Context, r io.Reader, blockSize int64) (chan block, func() int64) {
	ch := make(chan block, 16)
	done := make(chan int64, 1)

	go func() {
		var fileSize int64
		for index := int64(0); ; index++ {
			select {
			case <-ctx.Done():
				close(ch)
				done <- fileSize
				return
			default:
			}
			buf := make([]byte, blockSize)
			n, err := io.ReadFull(r, buf)
			if n == 0 {
				break
			}
			fileSize += int64(n)
			ch <- block{index: index, offset: index * blockSize, data: buf[:n]}
			if err != nil {
				break
			}
		}
		close(ch)
		done <- fileSize
	}()

	var sizeOnce sync.Once
	var fileSize int64
	return ch, func() int64 {
		sizeOnce.Do(func() { fileSize = <-done })
		return fileSize
	}
}

// --- hash pipeline ---

// processBlocks hashes blocks from the channel.
// If pw is non-nil, workers also compare hashes against pw.oldDigest
// and send changed blocks to pw for writing via its internal channel.
func processBlocks(ctx context.Context, blocks chan block, workers int, pw *patchWriter) []hashResult {
	resultsCh := make(chan hashResult, workers)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for b := range blocks {
				h := md5.Sum(b.data)
				hash := hex.EncodeToString(h[:])

				if pw != nil {
					pw.submitIfChanged(b.offset, hash, b.data)
				}

				resultsCh <- hashResult{
					index:  b.index,
					offset: b.offset,
					hash:   hash,
				}
			}
		}()
	}

	var results []hashResult
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for r := range resultsCh {
			results = append(results, r)
		}
	}()

	wg.Wait()
	close(resultsCh)
	collectorWg.Wait()

	if pw != nil {
		pw.closeInput()
	}

	if ctx.Err() != nil {
		fatal("cancelled")
	}

	sort.Slice(results, func(i, j int) bool { return results[i].index < results[j].index })
	return results
}

func toDigestBlocks(hrs []hashResult) []DigestBlock {
	out := make([]DigestBlock, len(hrs))
	for i, r := range hrs {
		out[i] = DigestBlock{Offset: r.offset, Hash: r.hash}
	}
	return out
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

func writeDigest(blocks []DigestBlock, blockSize int64, path string, outFile string) {
	df := DigestFile{
		Version:   1,
		Algorithm: "md5",
		BlockSize: blockSize,
		File:      path,
		Blocks:    blocks,
	}

	var out io.Writer = os.Stdout
	if outFile != "" {
		f, err := os.Create(outFile)
		if err != nil {
			fatal("error creating output file: %v", err)
		}
		defer f.Close()
		out = f
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(df); err != nil {
		fatal("error writing digest: %v", err)
	}
}

// --- patch I/O ---

// Patch format (BDPATCH3):
//   "BDPATCH3"          (8 bytes magic)
//   [entries]:
//     offset            (uint64 LE)
//     size              (uint32 LE)
//     data              (size bytes)
//   header JSON         (variable length)
//   header_offset       (uint64 LE — position where header JSON starts)

type patchEntry struct {
	offset int64
	data   []byte
}

// patchWriter writes a BDPATCH3 file. When oldDigest is provided, it accepts
// blocks via submitIfChanged() from hash workers, compares against the old digest,
// and writes changed blocks through an internal channel to a dedicated goroutine.
type patchWriter struct {
	f         *os.File
	blockSize int64
	oldDigest map[int64]string
	ch        chan patchEntry
	done      sync.WaitGroup
	count     int
}

func newPatchWriter(f *os.File, blockSize int64, oldDigest map[int64]string, bufSize int) *patchWriter {
	f.Write([]byte(patchMagic))
	pw := &patchWriter{
		f:         f,
		blockSize: blockSize,
		oldDigest: oldDigest,
		ch:        make(chan patchEntry, bufSize),
	}
	pw.done.Add(1)
	go func() {
		defer pw.done.Done()
		for e := range pw.ch {
			binary.Write(pw.f, binary.LittleEndian, uint64(e.offset))
			binary.Write(pw.f, binary.LittleEndian, uint32(len(e.data)))
			pw.f.Write(e.data)
			pw.count++
		}
	}()
	return pw
}

// submitIfChanged compares hash against oldDigest and queues the block for
// writing if it has changed. Called from hash workers.
func (pw *patchWriter) submitIfChanged(offset int64, hash string, data []byte) {
	oldHash, ok := pw.oldDigest[offset]
	if !ok || oldHash != hash {
		pw.ch <- patchEntry{offset: offset, data: data}
	}
}

// closeInput signals that no more blocks will be submitted.
// Blocks until all queued entries are written.
func (pw *patchWriter) closeInput() {
	close(pw.ch)
	pw.done.Wait()
}

func (pw *patchWriter) finalize() {
	headerOffset, _ := pw.f.Seek(0, io.SeekCurrent)
	header := PatchHeader{Version: 1, BlockSize: pw.blockSize, Count: pw.count}
	headerJSON, _ := json.Marshal(header)
	pw.f.Write(headerJSON)
	binary.Write(pw.f, binary.LittleEndian, uint64(headerOffset))
}

func readPatchHeader(pf *os.File) PatchHeader {
	magic := make([]byte, len(patchMagic))
	if _, err := io.ReadFull(pf, magic); err != nil || string(magic) != patchMagic {
		fatal("not a valid patch file (bad magic)")
	}

	pf.Seek(-8, io.SeekEnd)
	var headerOffset uint64
	binary.Read(pf, binary.LittleEndian, &headerOffset)

	pf.Seek(int64(headerOffset), io.SeekStart)
	fi, _ := pf.Stat()
	headerLen := fi.Size() - 8 - int64(headerOffset)
	headerBuf := make([]byte, headerLen)
	io.ReadFull(pf, headerBuf)

	var header PatchHeader
	if err := json.Unmarshal(headerBuf, &header); err != nil {
		fatal("error parsing patch header: %v", err)
	}

	pf.Seek(int64(len(patchMagic)), io.SeekStart)
	return header
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
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
		defer cancel()

		path := args[0]
		start := time.Now()

		blocks, getSize := readBlocks(ctx, path, digestBS, digestWorkers)
		results := processBlocks(ctx, blocks, digestWorkers, nil)
		fileSize := getSize()

		writeDigest(toDigestBlocks(results), digestBS, path, digestOut)
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
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
		defer cancel()

		path := args[0]

		oldBS, oldDigest, err := loadDigest(diffDigest)
		if err != nil {
			fatal("error loading digest: %v", err)
		}
		if oldBS > 0 && oldBS != diffBS {
			fmt.Fprintf(os.Stderr, "using block size %d from digest file\n", oldBS)
			diffBS = oldBS
		}

		patchFile, err := os.Create(diffPatch)
		if err != nil {
			fatal("error creating patch file: %v", err)
		}
		defer patchFile.Close()
		pw := newPatchWriter(patchFile, diffBS, oldDigest, diffWorkers)

		start := time.Now()

		blocks, getSize := readBlocks(ctx, path, diffBS, diffWorkers)
		results := processBlocks(ctx, blocks, diffWorkers, pw)
		fileSize := getSize()

		pw.finalize()

		writeDigest(toDigestBlocks(results), diffBS, path, diffOut)
		printStats(path, fileSize, diffBS, len(results), diffWorkers, start)
		fmt.Fprintf(os.Stderr, "changed blocks: %d / %d (%.1f%%)\n",
			pw.count, len(results), float64(pw.count)/float64(len(results))*100)
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
			fatal("error opening patch: %v", err)
		}
		defer pf.Close()

		header := readPatchHeader(pf)
		fmt.Fprintf(os.Stderr, "patch: version=%d, blockSize=%d, blocks=%d\n",
			header.Version, header.BlockSize, header.Count)

		tf, err := os.OpenFile(targetPath, os.O_WRONLY, 0)
		if err != nil {
			fatal("error opening target: %v", err)
		}
		defer tf.Close()

		applied := 0
		var totalBytes uint64
		for applied < header.Count {
			var offset uint64
			if err := binary.Read(pf, binary.LittleEndian, &offset); err != nil {
				fatal("error reading patch entry %d: %v", applied, err)
			}
			var size uint32
			binary.Read(pf, binary.LittleEndian, &size)
			data := make([]byte, size)
			if _, err := io.ReadFull(pf, data); err != nil {
				fatal("error reading patch data at offset %d: %v", offset, err)
			}
			if _, err := tf.WriteAt(data, int64(offset)); err != nil {
				fatal("error writing at offset %d: %v", offset, err)
			}
			applied++
			totalBytes += uint64(size)
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

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

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
