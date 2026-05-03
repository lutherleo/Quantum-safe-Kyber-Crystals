.PHONY: build test demo-eavesdrop demo-modify demo-replay benchmark clean rebuild

IMAGE := pq-secure-comm:latest
DC    := docker compose

build:
	$(DC) build

# Run a one-off container against the built image.
RUN := $(DC) run --rm --no-deps

demo-eavesdrop:
	$(RUN) --cap-add=NET_ADMIN --cap-add=NET_RAW \
		--entrypoint /app/scripts/demo_eavesdrop.sh attacker

demo-modify:
	$(RUN) --entrypoint /app/scripts/demo_modify.sh attacker

demo-replay:
	$(RUN) --entrypoint /app/scripts/demo_replay.sh attacker

# Run all three; exits non-zero if any fail.
test: build
	@set -e; \
	for d in demo-eavesdrop demo-modify demo-replay; do \
		echo "=== $$d ==="; \
		$(MAKE) $$d; \
	done; \
	echo "ALL DEMOS PASSED"

unit-test: build
	$(RUN) --entrypoint /app/build/test_protocol benchmark

benchmark: build
	$(DC) run --rm benchmark

clean:
	$(DC) down -v --remove-orphans 2>/dev/null || true
	rm -rf results/*.png results/*.csv results/*.pcap results/*.log

rebuild:
	$(DC) build --no-cache
