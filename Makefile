.PHONY: build build-server build-client build-all test clean deploy

# Default: build for current platform
build: build-server build-client

build-server:
	go build -trimpath -o bin/mirage-server ./cmd/mirage-server

build-client:
	go build -trimpath -o bin/mirage-client ./cmd/mirage-client

# Cross-compile for common targets
build-all:
	GOOS=linux GOARCH=amd64 go build -trimpath -o bin/mirage-server-linux-amd64 ./cmd/mirage-server
	GOOS=linux GOARCH=amd64 go build -trimpath -o bin/mirage-client-linux-amd64 ./cmd/mirage-client
	GOOS=linux GOARCH=arm64 go build -trimpath -o bin/mirage-server-linux-arm64 ./cmd/mirage-server
	GOOS=linux GOARCH=arm64 go build -trimpath -o bin/mirage-client-linux-arm64 ./cmd/mirage-client
	GOOS=darwin GOARCH=arm64 go build -trimpath -o bin/mirage-client-darwin-arm64 ./cmd/mirage-client
	GOOS=darwin GOARCH=amd64 go build -trimpath -o bin/mirage-client-darwin-amd64 ./cmd/mirage-client
	GOOS=windows GOARCH=amd64 go build -trimpath -o bin/mirage-client-windows-amd64.exe ./cmd/mirage-client

test:
	go test ./... -v -count=1

clean:
	rm -rf bin/
