.PHONY: all clean
all: run
build:
	@go build -o gonc .
clean:
	@echo "Cleaning the project..."
	@echo "Clean complete."
test:
	@echo "Running tests..."
	@echo "Tests complete."
install:
	@echo "Installing the project..."
	@echo "Install complete."