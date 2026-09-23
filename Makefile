.PHONY: all build frontend backend release test docker clean run

all: build

# 前端构建（产物复制到 cmd/cysec/webdist 嵌入二进制）
frontend:
	cd web && npm install && npm run build
	rm -rf server/cmd/cysec/webdist
	cp -r web/dist server/cmd/cysec/webdist

backend:
	cd server && CGO_ENABLED=0 go build -o ../dist/cysec ./cmd/cysec

build: frontend backend

# 双平台发布构建：Windows (dist/cysec.exe) + Linux amd64 (dist/cysec-linux-amd64)
# nuclei 引擎以 Go 库链接、SQLite 用 modernc 纯 Go 驱动，交叉编译无需 CGO
release: frontend
	cd server && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o ../dist/cysec.exe ./cmd/cysec
	cd server && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ../dist/cysec-linux-amd64 ./cmd/cysec

test:
	cd server && go test ./...

run: build
	./dist/cysec -config configs/config.yaml

docker:
	docker build -t cysec-scan:latest .

clean:
	rm -rf web/dist server/cmd/cysec/webdist dist
