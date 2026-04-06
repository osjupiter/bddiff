VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w

.PHONY: build clean release-local

build:
	go build -ldflags="$(LDFLAGS)" -o bddiff .

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
