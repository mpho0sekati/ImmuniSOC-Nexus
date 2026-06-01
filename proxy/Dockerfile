FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache gcc musl-dev

# Copy go mod and sum
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the proxy
RUN CGO_ENABLED=0 GOOS=linux go build -o proxy ./cmd/proxy

# Final stage
FROM alpine:latest

RUN apk add --no-cache ca-certificates

WORKDIR /root/

# Copy the binary
COPY --from=builder /app/proxy .

# Create logs directory
RUN mkdir logs

EXPOSE 8080

CMD ["./proxy"]
