BINARY_DIR    := ./bin
BINARY_NAME   := gonc
VERSION       := $(shell git describe --tags --always --dirty)
LDFLAGS       := -ldflags="-X main.version=$(VERSION) -w -s"

.PHONY: all
all: fmt test build

.PHONY: fmt
fmt: ## Format all Go source code in the project.
	@echo "--> Formatting code..."
	@go fmt ./...

.PHONY: build
build:
	@echo "Building binary..."
	@go build $(LDFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME) .

.PHONY: clean
clean:
	@echo "Cleaning the project..."
	@rm -rf ./bin
	@echo "Clean complete."

.PHONY: test
test:
	@echo "Running tests..."
	@go test -v -timeout 30s ./...

.PHONY: install
install:
	go install ./...

.PHONY: tidy
tidy:
	@echo "--> Tidying dependencies..."
	@go mod tidy
