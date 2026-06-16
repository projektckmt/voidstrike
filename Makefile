.PHONY: help up down logs test lint mcp-shell ci-easy fmt

help:
	@echo "Voidstrike — common targets"
	@echo "  make up         Bring up the management plane"
	@echo "  make up-dev     Plus local dev targets (DVWA, Juice Shop)"
	@echo "  make down       Stop everything"
	@echo "  make logs       Tail the gateway"
	@echo "  make test       Unit tests"
	@echo "  make lint       Ruff + mypy"
	@echo "  make ci-easy    Run the PR-time benchmark"

up:
	docker compose -f infra/docker-compose.yml up -d

up-dev:
	docker compose -f infra/docker-compose.yml -f infra/docker-compose.ops.yml \
	    --profile dev-targets up -d

down:
	docker compose -f infra/docker-compose.yml \
	    -f infra/docker-compose.ops.yml down

logs:
	docker compose -f infra/docker-compose.yml logs -f gateway

test:
	python -m pytest tests/unit/

lint:
	ruff check src/ tests/
	mypy src/

fmt:
	ruff format src/ tests/

ci-easy:
	python -m benchmark.ci_easy
