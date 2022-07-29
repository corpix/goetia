.DEFAULT_GOAL := all

.PHONY: all
all: lint test # test, check

.PHONY: help
help: # print defined targets and their comments
	@grep -Po '^[a-zA-Z%_/\-\s]+:+(\s.*$$|$$)' Makefile \
		| sort                                      \
		| sed 's|:.*#|#|;s|#\s*|#|'                 \
		| column -t -s '#' -o ' | '

.PHONY: test
test: # run unit tests
	go test -v ./...

.PHONY: lint
lint: # run linter
	golangci-lint --color=always --timeout=120s run ./...

.PHONY: fmt
fmt: # go fmt source files
	go fmt ./...
