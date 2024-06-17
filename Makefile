linter:=$(shell which golangci-lint 2>/dev/null || echo $(HOME)/go/bin/golangci-lint)

format:
	@gofmt -l  -w ./

check: test lint

lint:
	@test -z $(shell gofmt -l ./ | tee /dev/stderr) || (echo "[WARN] Fix formatting issues with 'make format'"; exit 1)
	@test -x $(linter) || (echo "Please install linter from https://github.com/golangci/golangci-lint/releases/tag/v1.49.0 to $(HOME)/go/bin")
	$(linter) run

test:
	go test ./... -v

.PHONY:  bin/estserver
bin/estserver:
	go build -o bin/estserver cmd/main.go
