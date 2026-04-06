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

type block struct {
	index  int64
	offset int64
	data   []byte
}

type hashResult struct {
	index  int64
	offset int64
	hash   string
	data   []byte // retained only when diff mode needs it
}

// --- block reading: produces chan block ---

// readBlocksFromFile reads blocks using parallel ReadAt and sends them to a channel.
func readBlocksFromFile(path string, blockSize int64, workers int) (chan block, int64) {
	fi, err := os.Stat(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fileSize := fi.Size()
	totalBlocks := (fileSize + blockSize - 1) / blockSize
	ch := make(chan block, workers*2)

	// Dispatch index-only jobs to reader workers, who ReadAt and send blocks
	type job struct{ index, offset, size int64 }
	jobs := make(chan job, workers*2)

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
			for j := range jobs {
				buf := make([]byte, j.size)
				n, _ := f.ReadAt(buf, j.offset)
				ch <- block{index: j.index, offset: j.offset, data: buf[:n]}
			}
		}()
	}

	go func() {
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
		close(ch)
	}()

	return ch, fileSize
}

// readBlocksFromStream reads blocks sequentially from an io.Reader.
func readBlocksFromStream(r io.Reader, blockSize int64) (chan block, chan int64) {
	ch := make(chan block, 16)
	done := make(chan int64, 1)

	go func() {
		var fileSize int64
		for index := int64(0); ; index++ {
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

	return ch, done
}

// --- hash pipeline: consumes chan block, produces []hashResult ---

func hashBlocks(blocks chan block, workers int, retainData bool) []hashResult {
	resultsCh := make(chan hashResult, workers)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for b := range blocks {
				h := md5.Sum(b.data)
				r := hashResult{
					index:  b.index,
					offset: b.offset,
					hash:   hex.EncodeToString(h[:]),
				}
				if retainData {
					r.data = b.data
				}
				resultsCh <- r
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

// --- diff logic ---

func findChangedBlocks(results []hashResult, oldDigest map[int64]string) []hashResult {
	var changed []hashResult
	for _, r := range results {
		if oldHash, ok := oldDigest[r.offset]; !ok || oldHash != r.hash {
			changed = append(changed, r)
		}
	}
	return changed
}

func writePatchBlocks(changed []hashResult, pw *patchWriter) {
	for _, r := range changed {
		pw.writeEntry(r.offset, r.data)
	}
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
		start := time.Now()

		var blocks chan block
		var fileSize int64

		if path == "-" {
			var done chan int64
			blocks, done = readBlocksFromStream(os.Stdin, digestBS)
			results := hashBlocks(blocks, digestWorkers, false)
			fileSize = <-done
			writeDigest(toDigestBlocks(results), digestBS, path, digestOut)
			printStats(path, fileSize, digestBS, len(results), digestWorkers, start)
		} else {
			blocks, fileSize = readBlocksFromFile(path, digestBS, digestWorkers)
			results := hashBlocks(blocks, digestWorkers, false)
			writeDigest(toDigestBlocks(results), digestBS, path, digestOut)
			printStats(path, fileSize, digestBS, len(results), digestWorkers, start)
		}
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

		start := time.Now()

		// Read blocks → hash (retaining data for patch) → find changed → write patch
		var blocks chan block
		var fileSize int64

		if path == "-" {
			var done chan int64
			blocks, done = readBlocksFromStream(os.Stdin, diffBS)
			results := hashBlocks(blocks, diffWorkers, true)
			fileSize = <-done
			changed := findChangedBlocks(results, oldDigest)
			writePatchBlocks(changed, pw)
			pw.finalize(len(changed))
			writeDigest(toDigestBlocks(results), diffBS, path, diffOut)
			printStats(path, fileSize, diffBS, len(results), diffWorkers, start)
			fmt.Fprintf(os.Stderr, "changed blocks: %d / %d (%.1f%%)\n",
				len(changed), len(results), float64(len(changed))/float64(len(results))*100)
		} else {
			blocks, fileSize = readBlocksFromFile(path, diffBS, diffWorkers)
			results := hashBlocks(blocks, diffWorkers, true)
			changed := findChangedBlocks(results, oldDigest)
			writePatchBlocks(changed, pw)
			pw.finalize(len(changed))
			writeDigest(toDigestBlocks(results), diffBS, path, diffOut)
			printStats(path, fileSize, diffBS, len(results), diffWorkers, start)
			fmt.Fprintf(os.Stderr, "changed blocks: %d / %d (%.1f%%)\n",
				len(changed), len(results), float64(len(changed))/float64(len(results))*100)
		}
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
