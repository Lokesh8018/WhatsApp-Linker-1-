# Stage 1: Build
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o wa-linker .

# Stage 2: Runtime
FROM alpine:latest

RUN apk add --no-cache ca-certificates sqlite-libs

WORKDIR /app

COPY --from=builder /app/wa-linker .
COPY --from=builder /app/index.html .
COPY --from=builder /app/admin.html .

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:${PORT:-8080}/health || exit 1

CMD ["./wa-linker"]
