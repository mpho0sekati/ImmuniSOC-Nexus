# Build a static Go binary
FROM golang:1.21-alpine AS builder
WORKDIR /app

# Cache go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-s -w' -o /app/neutrophil ./

# Minimal runtime image
FROM alpine:3.18
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/neutrophil /app/neutrophil
EXPOSE 8080 8090
ENTRYPOINT ["/app/neutrophil"]
