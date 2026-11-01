# Shortcuts for compose.yaml. Pass extra scan options with ARGS, e.g. make scan ARGS="--image node:22-slim".
COMPOSE ?= docker compose
ARGS ?= --path /scan

.PHONY: up down logs dashboard scan update test prod

up:  ## website at http://localhost:8080
	$(COMPOSE) up -d --build web proxy
	@echo "TrustWatch website: http://localhost:$${HTTP_PORT:-8080}"

down:
	$(COMPOSE) --profile dashboard down

logs:
	$(COMPOSE) logs -f

dashboard:  ## local dashboard at http://127.0.0.1:8765 (Docker images and SCAN_DIR)
	$(COMPOSE) --profile dashboard up -d --build dashboard
	@echo "TrustWatch dashboard: http://127.0.0.1:$${DASHBOARD_PORT:-8765}"

scan:  ## one-off scan; reports in ./reports
	mkdir -p reports
	@$(COMPOSE) run --rm --build scan $(ARGS); s=$$?; [ $$s -le 1 ] || exit $$s  # 1 only means findings were reported
	@echo "Reports: reports/trustwatch-report.json and .html"

update:  ## refresh Mozilla and incident data, then restart the website so it loads it
	$(COMPOSE) run --rm --build update
	$(COMPOSE) restart web 2>/dev/null || true

test:
	$(COMPOSE) run --rm --build test

prod:  ## on a server: SITE_ADDRESS=trustwatch.example.com make prod
	$(COMPOSE) -f compose.yaml -f compose.prod.yaml up -d --build web proxy
