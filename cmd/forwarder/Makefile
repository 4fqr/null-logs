BINARY=cmd/forwarder/null-logs-forwarder

all: $(BINARY)

$(BINARY):
	@echo "Building forwarder..."
	@mkdir -p cmd/forwarder
	@which go >/dev/null 2>&1 || (echo "Go not installed; install go to build the forwarder" && exit 1)
	# Build in this module directory
	GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o $(BINARY) .

clean:
	rm -f $(BINARY)

.PHONY: all clean