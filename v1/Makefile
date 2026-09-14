.DEFAULT_GOAL := help
PY ?= python3

help: ## список целей
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-10s %s\n", $$1, $$2}'

test: ## pytest
	$(PY) -m pytest tests -q

selftest: ## полный прогон пайплайна + проверка C++ хостовым g++
	$(PY) -m modkit selftest

runtime-check: ## строгая host C++17 проверка встроенного Android runtime v2
	$(PY) -m modkit runtime-check

demo: ## сгенерировать пример мода в ./demo-out
	$(PY) -m modkit selftest --keep ./demo-out
	@echo "проект: ./demo-out/module"

lint: ## ruff, если установлен
	@$(PY) -m ruff check modkit tests || true

clean:
	@rm -rf .pytest_cache demo-out
	@find . -name __pycache__ -type d -exec rm -rf {} +
