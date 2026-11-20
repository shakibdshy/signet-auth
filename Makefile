GO ?= go

# Developer tools installed with `go install` land in GOPATH/bin.
export PATH := $(shell $(GO) env GOPATH)/bin:$(PATH)

.PHONY: test integration cover lint vet vuln fmt fmt-check tidy check

test:
	$(GO) test -race ./...

integration:
	$(GO) test -race -count=1 ./store/postgres/... ./store/sqlite/...

cover:
	$(GO) test -race -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out

lint:
	golangci-lint run ./...

vet:
	$(GO) vet ./...

vuln:
	govulncheck ./...

fmt:
	gofmt -w .
	goimports -w .

fmt-check:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	@test -z "$$(goimports -l .)" || { echo "goimports needed:"; goimports -l .; exit 1; }

tidy:
	$(GO) mod tidy

check: fmt-check vet lint test vuln
