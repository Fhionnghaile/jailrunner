IMAGE ?= jailrunner
build: ; docker build -t $(IMAGE) .
run: build ; @echo 'print("hello from the cage")' | ./jailrunner/run.sh -
proof: build ; JR_IMAGE=$(IMAGE) ./proof/run.sh
api: build ; docker compose up
.PHONY: build run proof api
