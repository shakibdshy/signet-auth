GO ?= go

# Developer tools installed with `go install` land in GOPATH/bin.
export PATH := $(shell $(GO) env GOPATH)/bin:$(PATH)

.PHONY: test integration examples fuzz cover lint vet vuln fmt fmt-check tidy check generate generate-spec generate-types generate-check docs-site

test:
	$(GO) test -race ./...

integration:
	$(GO) test -race -count=1 ./store/postgres/... ./store/sqlite/...

examples:
	@for dir in examples/stdlib examples/chi examples/echo examples/gin examples/fiber; do \
		echo "building $$dir"; \
		(cd $$dir && $(GO) build ./...) || exit 1; \
	done

fuzz:
	@for target in FuzzArgonVerifier FuzzSessionTokenSignOut FuzzJSONRequestBodies FuzzOAuthState FuzzCSRFToken; do \
		echo "fuzzing $$target"; \
		$(GO) test -fuzz=$$target -fuzztime=10s ./tests || exit 1; \
	done

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

generate-spec:
	@mkdir -p api openapi
	$(GO) run ./cmd/signet-openapi > api/signet.openapi.json
	cp api/signet.openapi.json openapi/signet.openapi.json

generate-types:
	cd client/ts && npm run generate

generate: generate-spec generate-types

docs-site:
	cd docs-site && npm run docs:check && npm run sync:spec && npm run types:check && npm run build

# Regenerate into the working tree, compare with the committed artifacts, and
# restore the originals so a failure leaves the tree unchanged.
generate-check:
	@tmp=$$(mktemp -d); \
	cp api/signet.openapi.json $$tmp/spec.json; \
	cp openapi/signet.openapi.json $$tmp/embedded.json; \
	cp client/ts/src/schema.d.ts $$tmp/schema.d.ts; \
	$(MAKE) generate >/dev/null || exit 1; \
	if ! diff -u $$tmp/spec.json api/signet.openapi.json || \
	   ! diff -u $$tmp/embedded.json openapi/signet.openapi.json || \
	   ! diff -u $$tmp/schema.d.ts client/ts/src/schema.d.ts; then \
		cp $$tmp/spec.json api/signet.openapi.json; \
		cp $$tmp/embedded.json openapi/signet.openapi.json; \
		cp $$tmp/schema.d.ts client/ts/src/schema.d.ts; \
		rm -rf $$tmp; \
		echo "generated artifacts are stale; run make generate"; \
		exit 1; \
	fi; \
	rm -rf $$tmp; \
	echo "generated artifacts up to date"
