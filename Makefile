IMAGE      := globalprotect-manager
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
PLATFORMS := linux/amd64,linux/arm64
NEW_VOLUME ?= globalprotect-manager-data

.PHONY: help dev build build-frontend build-backend build-image build-arm64 push run stop logs tidy clean migrate-data

help:
	@echo ""
	@echo "  GlobalProtect Manager — Build Targets"
	@echo "  ─────────────────────────────────────────────────"
	@echo "  make dev              Start frontend+backend for local development"
	@echo "  make build            Build frontend then Go binary (host arch)"
	@echo "  make build-frontend   Build Svelte → backend/static/"
	@echo "  make build-backend    Build Go binary (host arch)"
	@echo "  make build-image      Build Docker image (host arch)"
	@echo "  make build-arm64      Build Docker image for linux/arm64"
	@echo "  make push             Multi-arch buildx push to registry"
	@echo "  make tidy             go mod tidy"
	@echo "  make migrate-data OLD_VOLUME=<name> [NEW_VOLUME=$(NEW_VOLUME)]"
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
	cd backend && CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=$(VERSION)" -o globalprotect-manager .
	@echo "✓ Binary → backend/globalprotect-manager"

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
	docker compose logs -f globalprotect-manager

migrate-data:
	@if [ -z "$(strip $(OLD_VOLUME))" ]; then \
		echo "ERROR: OLD_VOLUME is required"; \
		echo "Usage: make migrate-data OLD_VOLUME=<actual-old-volume> [NEW_VOLUME=$(NEW_VOLUME)]"; \
		exit 1; \
	fi
	@if [ "$(OLD_VOLUME)" = "$(NEW_VOLUME)" ]; then \
		echo "ERROR: OLD_VOLUME and NEW_VOLUME must be different"; \
		exit 1; \
	fi
	@if ! docker volume inspect "$(OLD_VOLUME)" >/dev/null 2>&1; then \
		echo "ERROR: source volume '$(OLD_VOLUME)' does not exist"; \
		exit 1; \
	fi
	@if docker volume inspect "$(NEW_VOLUME)" >/dev/null 2>&1; then \
		if ! docker run --rm \
			--mount "type=volume,src=$(NEW_VOLUME),dst=/data,readonly" \
			alpine:3.20 sh -c '[ -z "$$(find /data -mindepth 1 -maxdepth 1 -print -quit)" ]'; then \
			echo "ERROR: destination volume '$(NEW_VOLUME)' already contains data"; \
			exit 1; \
		fi; \
	else \
		docker volume create "$(NEW_VOLUME)" >/dev/null; \
	fi
	@docker run --rm \
		--mount "type=volume,src=$(OLD_VOLUME),dst=/source,readonly" \
		--mount "type=volume,src=$(NEW_VOLUME),dst=/data" \
		alpine:3.20 sh -c 'cp -a /source/. /data/'
	@docker run --rm \
		--mount "type=volume,src=$(OLD_VOLUME),dst=/source,readonly" \
		--mount "type=volume,src=$(NEW_VOLUME),dst=/data,readonly" \
		alpine:3.20 sh -c 'diff -qr /source /data'
	@echo "Migrated data from '$(OLD_VOLUME)' to '$(NEW_VOLUME)'; source was not modified."

# ── Utilities ────────────────────────────────────────────────────────────────
tidy:
	cd backend && go mod tidy

clean:
	rm -f backend/globalprotect-manager
	rm -rf backend/static/*
	@echo "Cleaned build artifacts (kept .gitkeep)"
	@touch backend/static/.gitkeep
