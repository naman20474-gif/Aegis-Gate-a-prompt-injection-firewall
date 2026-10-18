PYTHON ?= .venv/bin/python
NPM ?= npm

.PHONY: install test dev run backend frontend benchmark clean

install:
	@test -x $(PYTHON) || python3.11 -m venv .venv
	@$(PYTHON) -m pip install -r requirements.lock
	@$(NPM) ci

test:
	@$(PYTHON) -m pytest
	@$(NPM) run typecheck

# Start both local services; Ctrl-C terminates the backend and Vite child.
dev:
	@trap 'kill 0' INT TERM EXIT; \
	$(PYTHON) -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 & \
	$(NPM) run dev -- --host 127.0.0.1

run:
	@$(PYTHON) -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000

backend: run
frontend:
	@$(NPM) run dev -- --host 127.0.0.1

benchmark:
	@$(PYTHON) -m backend.app.bench.runner

clean:
	@rm -rf dist frontend/.vite
