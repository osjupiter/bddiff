package main

import (
	"bufio"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

const patchMagic = "BDPATCH1"

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

	patchFile, err := os.Create(diffPatch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating patch file: %v\n", err)
		os.Exit(1)
	}
	defer patchFile.Close()
	writePatchHeader(patchFile, diffBS)

	start := time.Now()

	var results []BlockResult
	var fileSize int64
	var changedCount int

	if isStdin {
		results, fileSize, changedCount = processStdin(os.Stdin, diffBS, diffWorkers, oldDigest, patchFile)
	} else {
		results, fileSize, changedCount = processFile(path, diffBS, diffWorkers, oldDigest, patchFile)
	}

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

	magic := make([]byte, len(patchMagic))
	if _, err := io.ReadFull(pf, magic); err != nil || string(magic) != patchMagic {
		fmt.Fprintf(os.Stderr, "error: not a valid patch file\n")
		os.Exit(1)
	}

	var blockSize uint64
	binary.Read(pf, binary.LittleEndian, &blockSize)

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

	fmt.Fprintf(os.Stderr, "applied %d blocks (%.1f MB) to %s\n", applied, float64(totalBytes)/1024/1024, targetPath)
}

// --- core logic ---

func loadDigest(path string) (int64, map[int64]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()

	var blockSize int64
	digests := make(map[int64]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			for _, part := range strings.Fields(line) {
				if strings.HasPrefix(part, "bs=") {
					blockSize, _ = strconv.ParseInt(part[3:], 10, 64)
				}
			}
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		offset, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			continue
		}
		digests[offset] = parts[1]
	}
	return blockSize, digests, scanner.Err()
}

func processFile(path string, blockSize int64, workers int, oldDigest map[int64]string, patchFile *os.File) ([]BlockResult, int64, int) {
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
	if oldDigest != nil && patchFile != nil {
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
			writePatchEntry(patchFile, r.Offset, buf[:n])
		}
	}

	return results, fileSize, changedCount
}

func processStdin(r io.Reader, blockSize int64, workers int, oldDigest map[int64]string, patchFile *os.File) ([]BlockResult, int64, int) {
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
				if changed && patchFile != nil {
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
			if patchFile != nil && c.data != nil {
				writePatchEntry(patchFile, c.Offset, c.data)
			}
		}
	}

	return results, fileSize, changedCount
}

func writeDigest(results []BlockResult, blockSize int64, path string, outFile string) {
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
	w := bufio.NewWriter(out)
	fmt.Fprintf(w, "# bddiff md5 bs=%d file=%s\n", blockSize, path)
	for _, r := range results {
		fmt.Fprintf(w, "%d\t%s\n", r.Offset, r.Hash)
	}
	w.Flush()
}

func writePatchHeader(w io.Writer, blockSize int64) {
	w.Write([]byte(patchMagic))
	binary.Write(w, binary.LittleEndian, uint64(blockSize))
}

func writePatchEntry(w io.Writer, offset int64, data []byte) {
	binary.Write(w, binary.LittleEndian, uint64(offset))
	binary.Write(w, binary.LittleEndian, uint32(len(data)))
	w.Write(data)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
