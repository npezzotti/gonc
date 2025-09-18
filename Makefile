BINARY_DIR    := ./bin
BINARY_NAME   := gonc
VERSION       := dev
LDFLAGS       := -ldflags="-X main.version=$(VERSION) -w -s"

.PHONY: all tidy fmt test install build release clean

all: build

tidy:
	go mod tidy

fmt:
	go fmt ./...

test:
	@echo "Running tests..."
	@go test -v -timeout 30s ./...

install: tidy
	go install ./...

build:
	@echo "Building $(BINARY_NAME) version $(VERSION) for $(GOOS)/$(GOARCH)..."
	@mkdir -p $(BINARY_DIR)
	@go build $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME)_$(VERSION)_$(GOOS)_$(GOARCH) ./...
	@echo "Build complete."
	@echo "Binary located at $(BINARY_DIR)/$(BINARY_NAME)"

release: clean
	@echo "Building release binaries for version $(VERSION)..."
	GOOS=linux GOARCH=amd64 $(MAKE) build
	GOOS=windows GOARCH=amd64 $(MAKE) build
	GOOS=darwin GOARCH=amd64 $(MAKE) build
	GOOS=darwin GOARCH=arm64 $(MAKE) build
	@echo "Archiving binaries..."
	tar -czf $(BINARY_DIR)/$(BINARY_NAME)_$(VERSION)_linux_amd64.tar.gz -C $(BINARY_DIR) $(BINARY_NAME)_$(VERSION)_linux_amd64
	zip -j $(BINARY_DIR)/$(BINARY_NAME)_$(VERSION)_windows_amd64.zip $(BINARY_DIR)/$(BINARY_NAME)_$(VERSION)_windows_amd64
	tar -czf $(BINARY_DIR)/$(BINARY_NAME)_$(VERSION)_darwin_amd64.tar.gz -C $(BINARY_DIR) $(BINARY_NAME)_$(VERSION)_darwin_amd64
	tar -czf $(BINARY_DIR)/$(BINARY_NAME)_$(VERSION)_darwin_arm64.tar.gz -C $(BINARY_DIR) $(BINARY_NAME)_$(VERSION)_darwin_arm64

clean:
	rm -rf ./bin
