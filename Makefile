.PHONY: test
test:
	go test ./... -p 1 -race

.PHONY: doc
doc:
	go run internal/docs/main.go

.PHONY: build
build:
	docker build -f dev.Dockerfile -t gothdns .

.PHONY: up
up:
	docker stop gothdns || true
	docker rm gothdns || true
	docker run --name gothdns --rm -w /app -d -v $$(pwd):/app gothdns
