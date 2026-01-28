.PHONY: build run test clean docker geoip

APP_NAME=defenra-agent
GEOIP_DB=GeoLite2-City.mmdb

build:
	@echo "Building $(APP_NAME)..."
	go build -o $(APP_NAME) .

run: build
	@echo "Running $(APP_NAME)..."
	./$(APP_NAME)

test:
	@echo "Running tests..."
	go test -v ./...

clean:
	@echo "Cleaning up..."
	rm -f $(APP_NAME)
	rm -f $(APP_NAME).exe

docker:
	@echo "Building Docker image..."
	docker build -t defenra-agent:latest .

docker-run:
	@echo "Running Docker container..."
	docker run -d \
		-p 53:53/udp \
		-p 53:53/tcp \
		-p 80:80 \
		-p 443:443 \
		-p 8080:8080 \
		--env-file .env \
		--name defenra-agent \
		defenra-agent:latest

geoip:
	@echo "Downloading GeoIP database..."
	wget -O $(GEOIP_DB) https://github.com/Defenra/DefenraCore/raw/refs/heads/main/data/GeoLite2-City.mmdb

deps:
	@echo "Downloading dependencies..."
	go mod download

tidy:
	@echo "Tidying dependencies..."
	go mod tidy

fmt:
	@echo "Formatting code..."
	go fmt ./...

vet:
	@echo "Vetting code..."
	go vet ./...

lint: fmt vet
	@echo "Linting complete"

all: deps lint build

.DEFAULT_GOAL := build
