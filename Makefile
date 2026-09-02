BINARY  := bin/agentgraph
PKG     := ./cmd/agentgraph

.PHONY: build test vet fmt lint demo clean install

build:
	go build -o $(BINARY) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

lint:
	gofmt -l .
	go vet ./...

demo: build
	$(BINARY) demo

install:
	go install $(PKG)

clean:
	rm -rf bin/
