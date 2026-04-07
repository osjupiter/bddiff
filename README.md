# bddiff

Parallel block-level MD5 digest and binary diff tool for large files and block devices.

Generates fixed-size block checksums, detects changed blocks by comparing digests, and produces compact binary patches. Designed for efficiently syncing multi-GB to TB-scale files (disk images, VM snapshots, database dumps, etc.) where only a fraction of blocks change between versions.

## Why bddiff?

Existing tools each cover part of the problem, but none combine all of these:

| Tool | Parallel | Standalone digest | Binary patch | Notes |
|------|----------|-------------------|--------------|-------|
| hashdeep | No | Yes | No | Single-threaded, digest only |
| rsync/rdiff | No | Yes | Yes | File-oriented, rolling checksum not suited for block devices |
| bdsync | No | Weak | Yes | Requires network, no standalone digest export |
| xdelta | No | No | Yes | Whole-file delta, not block-level |
| **bddiff** | **Yes** | **Yes** | **Yes** | Fixed-block, parallel, works on files and block devices |

## Install

Download a binary from [Releases](https://github.com/osjupiter/bddiff/releases), or build from source:

```bash
go install github.com/osjupiter/bddiff@latest
```

## Usage

### Generate a digest

```bash
# From a file (parallel read)
bddiff digest -j 16 -o baseline.digest /dev/sda

# From stdin (streaming)
ssh remote dd if=/dev/sda | bddiff digest -o baseline.digest -
```

### Detect changes and create a patch

```bash
# Compare current state against baseline, output new digest + binary patch
bddiff diff -j 16 -d baseline.digest -p changes.patch -o current.digest /dev/sda

# From stdin
cat snapshot.img | bddiff diff -d baseline.digest -p changes.patch -o current.digest -
```

### Apply a patch

```bash
bddiff apply changes.patch /dev/sda
```

### Typical workflow

```bash
# 1. Take initial digest
bddiff digest -j 16 -o v1.digest /data/disk.img

# 2. After some changes, generate diff
bddiff diff -j 16 -d v1.digest -p v1-to-v2.patch -o v2.digest /data/disk.img
# changed blocks: 1024 / 10240 (10.0%)

# 3. Transfer only the patch (much smaller than full image)
scp v1-to-v2.patch remote:/tmp/

# 4. Apply on the remote side
ssh remote bddiff apply /tmp/v1-to-v2.patch /data/disk.img
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-b, --block-size` | `1048576` (1 MB) | Block size in bytes |
| `-j, --jobs` | Number of CPUs | Parallel workers |
| `-o, --output` | stdout | Output digest file |
| `-d, --digest` | (required for diff) | Old digest file to compare against |
| `-p, --patch` | (required for diff) | Output patch file |

## Performance

Measured on a 10 GB random file (16-core machine):

| Mode | Workers | Time | Throughput |
|------|---------|------|------------|
| digest (file) | 1 | 17.2s | 595 MB/s |
| digest (file) | 16 | 3.0s | 3,368 MB/s |
| digest (stdin) | 16 | 8.2s | 1,250 MB/s |
| diff (file, 10% changed) | 16 | 4.6s | 2,214 MB/s |

## Digest format

JSON:

```json
{
  "version": 1,
  "algorithm": "md5",
  "blockSize": 1048576,
  "file": "/dev/sda",
  "blocks": [
    {"offset": 0, "hash": "cff2e61d033889d72fd59cf7771b72e1"},
    {"offset": 1048576, "hash": "4f4a18941dc0baf6fdba83258582e52d"}
  ]
}
```

## Patch format

Binary with JSON trailer (variable-length, no fixed padding):

```
"BDPATCH3"        (8 bytes magic)
[entries]:
  offset          (uint64 LE)
  size            (uint32 LE)
  data            (size bytes)
header JSON       (variable length)
header_offset     (uint64 LE — byte position where header JSON starts)
```

The header is written at the end of the file after all entries, so it can include the exact block count without pre-allocation or seek-back.

## License

MIT
