.PHONY: all build frontend backend test docker clean run

all: build

# 前端构建（产物复制到 cmd/cysec/webdist 嵌入二进制）
frontend:
	cd web && npm install && npm run build
	rm -rf server/cmd/cysec/webdist
	cp -r web/dist server/cmd/cysec/webdist

backend:
	cd server && CGO_ENABLED=0 go build -o ../dist/cysec ./cmd/cysec

build: frontend backend

test:
	cd server && go test ./...

run: build
	./dist/cysec -config configs/config.yaml

docker:
	docker build -t cysec-scan:latest .

clean:
	rm -rf web/dist server/cmd/cysec/webdist dist
