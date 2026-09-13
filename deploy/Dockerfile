# ---- 前端构建 ----
FROM node:22-alpine AS web
WORKDIR /app
COPY web/package.json web/package-lock.json* ./
RUN npm install
COPY web/ .
RUN npm run build

# ---- 后端构建 ----
FROM golang:1.26-alpine AS server
WORKDIR /app
COPY server/go.mod server/go.sum ./
RUN go mod download
COPY server/ .
COPY --from=web /app/dist cmd/cysec/webdist
RUN CGO_ENABLED=0 go build -o /cysec ./cmd/cysec

# ---- 运行镜像 ----
FROM alpine:3.20
RUN adduser -D -u 10001 cysec
WORKDIR /app
COPY --from=server /cysec /app/cysec
COPY configs/config.yaml /app/configs/config.yaml
RUN mkdir -p /app/data && chown -R cysec:cysec /app
USER cysec
EXPOSE 8080
VOLUME ["/app/data"]
ENTRYPOINT ["/app/cysec", "-config", "/app/configs/config.yaml"]
