IMAGE     := kyle-proxy
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
PLATFORMS := linux/amd64,linux/arm64

.PHONY: help dev build build-frontend build-backend build-image push clean

help:
	@echo ""
	@echo "  Kyle VPN Proxy — Build Targets"
	@echo "  ─────────────────────────────────────────────────"
	@echo "  make dev              Start frontend+backend for local development"
	@echo "  make build            Build frontend then Go binary (host arch)"
	@echo "  make build-frontend   Build Svelte → backend/static/"
	@echo "  make build-backend    Build Go binary (host arch)"
	@echo "  make build-image      Build Docker image (host arch)"
	@echo "  make build-arm64      Build Docker image for linux/arm64"
	@echo "  make push             Multi-arch buildx push to registry"
	@echo "  make tidy             go mod tidy"
	@echo "  make clean            Remove build artifacts"
	@echo ""

# ── Development ──────────────────────────────────────────────────────────────
dev:
	@echo "Starting dev servers…"
	@(cd frontend && npm install && npm run dev) &
	@(cd backend && go run .) &
	@wait

# ── Production build ─────────────────────────────────────────────────────────
build: build-frontend build-backend

build-frontend:
	@echo "→ Building Svelte frontend…"
	cd frontend && npm install && npm run build
	@echo "✓ Frontend output → backend/static/"

build-backend:
	@echo "→ Building Go binary…"
	cd backend && CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=$(VERSION)" -o kyle-proxy .
	@echo "✓ Binary → backend/kyle-proxy"

# ── Docker ───────────────────────────────────────────────────────────────────
build-image: ## Build for current host architecture
	docker build -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

build-arm64: ## Build for linux/arm64 (TV Box target)
	docker buildx build \
	  --platform linux/arm64 \
	  --tag $(IMAGE):$(VERSION)-arm64 \
	  --load \
	  .

push: ## Multi-arch build and push (needs REGISTRY set)
	docker buildx build \
	  --platform $(PLATFORMS) \
	  --tag $(REGISTRY)/$(IMAGE):$(VERSION) \
	  --tag $(REGISTRY)/$(IMAGE):latest \
	  --push \
	  .

run: ## Run with docker-compose
	docker compose up -d

stop:
	docker compose down

logs:
	docker compose logs -f kyle-proxy

# ── Utilities ────────────────────────────────────────────────────────────────
tidy:
	cd backend && go mod tidy

clean:
	rm -f backend/kyle-proxy
	rm -rf backend/static/*
	@echo "Cleaned build artifacts (kept .gitkeep)"
	@touch backend/static/.gitkeep
