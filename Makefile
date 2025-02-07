.PHONY: test
test:
	go test ./... -p 1 -race

.PHONY: doc
doc:
	go run internal/docs/main.go

.PHONY: build
build:
	docker build -f dev.Dockerfile -t gauth-dns .

.PHONY: up
up:
	docker stop gauth-dns || true
	docker rm gauth-dns || true
	docker run --name gauth-dns --rm -w /app -d -v $$(pwd):/app gauth-dns
