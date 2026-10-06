# donothack 构建与验收
#
# Windows 上 make 不一定有，等价脚本见 scripts/lint.ps1 与 scripts/bench.ps1。
#
# 提交前必须全绿：make check
# 出发布产物：make dist

SHELL := /bin/sh

BINARY  := donothack
MODULE  := donothack
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# -s -w 去掉符号与调试信息；-trimpath 去掉本机路径。
# 版本信息用 ldflags 注入，前端资源的缓存失效也依赖这个版本号（见 docs/CONSOLE.md §6）。
LDFLAGS := -s -w \
  -X $(MODULE)/internal/version.Version=$(VERSION) \
  -X $(MODULE)/internal/version.Commit=$(COMMIT) \
  -X $(MODULE)/internal/version.Date=$(DATE)

# GOAMD64 必须是 v1：低配 VPS 的 CPU 经常是老型号，v3 需要 AVX2，跑起来会直接
# illegal instruction 崩掉，而不是"变慢"。默认值就是 v1，这里显式钉死防止手滑。
GOAMD64 ?= v1
export GOAMD64

.PHONY: all
all: check

.PHONY: fmt
fmt:
	gofmt -l . | tee /dev/stderr | (! read)   # 有输出即失败

.PHONY: fmt-fix
fmt-fix:
	gofmt -w .

.PHONY: vet
vet:
	go vet ./...

.PHONY: test
test:
	go test ./...

.PHONY: test-race
test-race:
	go test -race ./...

.PHONY: bench
bench:
	go test -run '^$$' -bench . -benchmem ./...

.PHONY: check
check: fmt vet test

.PHONY: build
build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY) ./cmd/donothack

.PHONY: dist
dist:
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64   ./cmd/donothack
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64   ./cmd/donothack
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe ./cmd/donothack
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/loadgen-linux-amd64 ./cmd/loadgen
	@ls -lh dist/

.PHONY: run
run: build
	./dist/$(BINARY) -c config.example.yaml

.PHONY: budget
budget: build
	./dist/$(BINARY) -c config.example.yaml -print-budget

.PHONY: clean
clean:
	rm -rf dist
