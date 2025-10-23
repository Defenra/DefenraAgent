FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o defenra-agent .

FROM alpine:latest

RUN apk --no-cache add ca-certificates wget

WORKDIR /app

COPY --from=builder /app/defenra-agent .

RUN wget -O GeoLite2-City.mmdb https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb

EXPOSE 53/udp 53/tcp 80/tcp 443/tcp 8080/tcp

CMD ["./defenra-agent"]
