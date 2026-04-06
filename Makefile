VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w

.PHONY: build test bench clean release-local

build:
	go build -ldflags="$(LDFLAGS)" -o bddiff .

test:
	go test -v ./...

bench: build
	@echo "=== Creating 10GB test file ==="
	dd if=/dev/urandom of=/tmp/bddiff-bench-orig.bin bs=1M count=10240 status=progress
	@echo "=== Digest ==="
	./bddiff digest -j $$(nproc) -o /tmp/bddiff-bench.digest /tmp/bddiff-bench-orig.bin
	@echo "=== Creating modified file (10% changed) ==="
	cp /tmp/bddiff-bench-orig.bin /tmp/bddiff-bench-mod.bin
	python3 -c "import random; random.seed(42); [__import__('subprocess').run(['dd','if=/dev/urandom','of=/tmp/bddiff-bench-mod.bin','bs=1048576','count=1','seek='+str(b),'conv=notrunc'],capture_output=True) for b in random.sample(range(10240),1024)]"
	@echo "=== Diff ==="
	./bddiff diff -j $$(nproc) -d /tmp/bddiff-bench.digest -p /tmp/bddiff-bench.patch -o /tmp/bddiff-bench-mod.digest /tmp/bddiff-bench-mod.bin
	@echo "=== Apply ==="
	cp /tmp/bddiff-bench-orig.bin /tmp/bddiff-bench-apply.bin
	./bddiff apply /tmp/bddiff-bench.patch /tmp/bddiff-bench-apply.bin
	@echo "=== Verify ==="
	@md5sum /tmp/bddiff-bench-mod.bin /tmp/bddiff-bench-apply.bin | awk '{h[NR]=$$1} END{if(h[1]==h[2]) print "PASS: files match"; else {print "FAIL: mismatch"; exit 1}}'
	rm -f /tmp/bddiff-bench-*.bin /tmp/bddiff-bench.digest /tmp/bddiff-bench.patch /tmp/bddiff-bench-mod.digest

clean:
	rm -rf bddiff dist/

release-local: clean
	mkdir -p dist
	GOOS=linux  GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o dist/bddiff-linux-amd64 .
	GOOS=linux  GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o dist/bddiff-linux-arm64 .
	GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o dist/bddiff-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o dist/bddiff-darwin-arm64 .
	@echo "Built $(VERSION) -> dist/"
	@ls -lh dist/
