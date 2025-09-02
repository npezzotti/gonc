.PHONY: all clean build test install
all: test build
build:
	@go build -o ./bin/gonc .
clean:
	@echo "Cleaning the project..."
	@rm -rf ./bin
	@echo "Clean complete."
test:
	@echo "Running tests..."
	@go test -v -timeout 30s ./...
install:
	go install ./...