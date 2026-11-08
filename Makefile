PORT ?= 8861

.PHONY: install test lint report gate gate-weak diff demo run stack screenshot docker-build up clean

install:
	uv sync --python 3.12

test:
	uv run pytest -q

lint:
	uvx ruff check .

report:  ## planted event results, friction, and least-privilege recommendations (seed 7)
	uv run ztgate report

gate:  ## the CI gate: every planted event caught, false denies under 2%
	uv run ztgate gate --max-false-deny-rate 0.02

gate-weak:  ## the gate on a deliberately loosened overlay (exits 1)
	-uv run ztgate gate --overlay examples/policies-weak

diff:  ## what the loosened payroll policy would newly allow
	-uv run ztgate diff examples/policies-weak/payroll.yaml

demo:  ## end-to-end proxy demo in one process
	uv run ztgate demo

run:  ## admin service and UI only
	uv run ztgate serve --port $(PORT)

stack:  ## admin, proxy, and both backends in one process (ports PORT to PORT+3)
	uv run ztgate stack --port $(PORT)

screenshot:  ## needs `make stack` running and Google Chrome
	uv run python scripts/screenshot.py --port $(PORT)

docker-build:
	docker build -t zero-trust-gate .

up:
	docker compose up --build

clean:
	rm -rf .pytest_cache .ruff_cache data gate-summary.md
