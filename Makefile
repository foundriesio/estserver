format:
	@gofmt -l  -w ./

check: test
	@test -z $(shell gofmt -l ./ | tee /dev/stderr) || (echo "[WARN] Fix formatting issues with 'make format'"; exit 1)
	@test -x $(linter) || (echo "Please install linter from https://github.com/golangci/golangci-lint/releases/tag/v1.25.1 to $(HOME)/go/bin")
	$(linter) run

test:
	go test ./... -v

.PHONY:  bin/estserver
bin/estserver:
	go build -o bin/estserver cmd/main.go