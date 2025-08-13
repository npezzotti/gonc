.PHONY: all clean
all: run
build:
	@go build -o ./bin/gonc .
clean:
	@echo "Cleaning the project..."
	@rm -rf ./bin
	@echo "Clean complete."
test:
	@echo "Running tests..."
	@go test -v ./...
install:
	go install ./...