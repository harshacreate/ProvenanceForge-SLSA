.PHONY: help setup build enroll verify tamper test clean

help:
	@echo "setup   - install dependencies"
	@echo "build   - run the pipeline, emit a signed release bundle (never enrolls trust)"
	@echo "enroll  - admin step: enroll the builder's key into the trust store"
	@echo "verify  - build, enroll (admin), then verify against the ACTUAL artifact"
	@echo "tamper  - run the controlled tamper experiments"
	@echo "test    - run the pytest suite"

setup:
	python3 -m pip install -r requirements.txt

build:
	python3 -m pipeline.build

enroll:
	python3 -m pipeline.enroll \
		--builder "https://example/pipeline/github-actions@refs/heads/main" \
		--key out/keys/builder_ed25519.pub

# Demo flow: build (cannot enroll) -> admin enrolls the key -> verify recomputes
# the artifact digest independently of the bundle.
verify: build enroll
	python3 -m pipeline.verify --out out

tamper:
	python3 -m tamper.experiments

test:
	python3 -m pytest -q

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache out trust
