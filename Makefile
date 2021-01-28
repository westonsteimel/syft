.SHELLFLAGS := -o pipefail -ec
SHELL := /bin/bash

BIN := syft
TEMPDIR := ./.tmp
RESULTSDIR = $(TEMPDIR)/results
COVER_REPORT = $(RESULTSDIR)/cover.report
COVER_TOTAL = $(RESULTSDIR)/cover.total
LINTCMD = $(TEMPDIR)/golangci-lint run --tests=false --config .golangci.yaml
ACC_TEST_IMAGE := centos:8.2.2004
ACC_DIR := ./test/acceptance
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)
# the quality gate lower threshold for unit test total % coverage (by function statements)
COVERAGE_THRESHOLD := 68
# CI cache busting values; change these if you want CI to not use previous stored cache
COMPARE_CACHE_BUSTER := "f7e689d76a9"
INTEGRATION_CACHE_BUSTER := "789bacdf"

## Build variables
DISTDIR := ./dist
SNAPSHOTDIR := ./snapshot
COMMIT = $(shell git log --format=%H -n 1)
DATE = $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GITTREESTATE = $(if $(shell git status --porcelain),dirty,clean)
SNAPSHOT_CMD = $(shell realpath $(shell pwd)/$(SNAPSHOTDIR)/syft_linux_amd64/syft)

# Homebrew variables
HOMEBREW_FORMULA_FILE = "$(DISTDIR)/$(BIN).rb"
BREW_DIR = "$(TEMPDIR)/homebrew"
BREW_BIN_DIR = "$(BREW_DIR)/bin"
BREW_CMD = "$(BREW_BIN_DIR)/brew"

ifeq "$(strip $(VERSION_TAG))" ""
	override VERSION_TAG = $(shell git describe --always --tags --dirty)
endif

# Version variables and functions
is_dirty = $(findstring dirty,$(1))
get_version_from_version_tag = $(shell echo "$(1)" | tr -d 'v')
VERSION = $(call get_version_from_version_tag,$(VERSION_TAG))
major = $(shell echo "$(1)" | cut -d '.' -f 1)
minor = $(shell echo "$(1)" | cut -d '.' -f 2)
patch = $(shell echo "$(1)" | cut -d '.' -f 3)

# used to generate the changelog from the second to last tag to the current tag (used in the release pipeline when the release tag is in place)
LAST_TAG = $(shell git describe --abbrev=0 --tags $(shell git rev-list --tags --max-count=1))
SECOND_TO_LAST_TAG = $(shell git describe --abbrev=0 --tags $(shell git rev-list --tags --skip=1 --max-count=1))

CONTAINER_IMAGE_REPOSITORY := "anchore/$(BIN)"
CONTAINER_IMAGE_TAG_MAJOR := "$(CONTAINER_IMAGE_REPOSITORY):$(call major,$(VERSION))"
CONTAINER_IMAGE_TAG_MINOR := "$(CONTAINER_IMAGE_REPOSITORY):$(call major,$(VERSION)).$(call minor,$(VERSION))"
CONTAINER_IMAGE_TAG_PATCH := "$(CONTAINER_IMAGE_REPOSITORY):$(call major,$(VERSION)).$(call minor,$(VERSION)).$(call patch,$(VERSION))"
CONTAINER_IMAGE_TAG_LATEST := "$(CONTAINER_IMAGE_REPOSITORY):latest"

asset_url = $(shell cat $(1) | jq '.assets[] | select(.name | contains($(2))) | .browser_download_url')
sha256 = $(shell openssl dgst -sha256 "$(1)" | cut -d ' ' -f 2)

## Variable assertions

ifndef TEMPDIR
	$(error TEMPDIR is not set)
endif

ifndef RESULTSDIR
	$(error RESULTSDIR is not set)
endif

ifndef ACC_DIR
	$(error ACC_DIR is not set)
endif

ifndef DISTDIR
	$(error DISTDIR is not set)
endif

ifndef SNAPSHOTDIR
	$(error SNAPSHOTDIR is not set)
endif

define title
    @printf '$(TITLE)$(1)$(RESET)\n'
endef

## Tasks

.PHONY: all
all: clean static-analysis test ## Run all linux-based checks (linting, license check, unit, integration, and linux acceptance tests)
	@printf '$(SUCCESS)All checks pass!$(RESET)\n'

.PHONY: test
test: unit validate-cyclonedx-schema integration acceptance-linux ## Run all tests (currently unit, integration, and linux acceptance tests)

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'

.PHONY: bootstrap-ci-linux
bootstrap-ci-linux: bootstrap
	DEBIAN_FRONTEND=noninteractive sudo apt update && sudo -E apt install -y bc jq libxml2-utils
	github_changelog_generator --version || sudo gem install github_changelog_generator

.PHONY: bootstrap-ci-mac
bootstrap-ci-mac: bootstrap

.PHONY: bootstrap
bootstrap: ## Download and install all go dependencies (+ prep tooling in the ./tmp dir)
	$(call title,Bootstrapping dependencies)
	@pwd
	# prep temp dirs
	mkdir -p $(TEMPDIR)
	mkdir -p $(RESULTSDIR)
	# install go dependencies
	go mod download
	# install utilities
	[ -f "$(TEMPDIR)/golangci" ] || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TEMPDIR)/ v1.26.0
	[ -f "$(TEMPDIR)/bouncer" ] || curl -sSfL https://raw.githubusercontent.com/wagoodman/go-bouncer/master/bouncer.sh | sh -s -- -b $(TEMPDIR)/ v0.2.0
	[ -f "$(TEMPDIR)/goreleaser" ] || curl -sfL https://install.goreleaser.com/github.com/goreleaser/goreleaser.sh | sh -s -- -b $(TEMPDIR)/ v0.140.0
	[ -f "$(TEMPDIR)/nfpm" ] || curl -sfL curl -sfL https://install.goreleaser.com/github.com/goreleaser/nfpm.sh | sh -s -- -b $(TEMPDIR)/ v2.2.2
	[ -f "$(BREW_CMD)" ] || (mkdir -p "$(BREW_DIR)" && curl -L https://github.com/Homebrew/brew/tarball/master | tar -xz --strip 1 -C "$(BREW_DIR)")

.PHONY: static-analysis
static-analysis: lint check-licenses

.PHONY: lint
lint: ## Run gofmt + golangci lint checks
	$(call title,Running linters)
	# ensure there are no go fmt differences
	@printf "files with gofmt issues: [$(shell gofmt -l -s .)]\n"
	@test -z "$(shell gofmt -l -s .)"

	# run all golangci-lint rules
	$(LINTCMD)

	# go tooling does not play well with certain filename characters, ensure the common cases don't result in future "go get" failures
	$(eval MALFORMED_FILENAMES := $(shell find . | grep -e ':'))
	@bash -c "[[ '$(MALFORMED_FILENAMES)' == '' ]] || (printf '\nfound unsupported filename characters:\n$(MALFORMED_FILENAMES)\n\n' && false)"

.PHONY: lint-fix
lint-fix: ## Auto-format all source code + run golangci lint fixers
	$(call title,Running lint fixers)
	gofmt -w -s .
	$(LINTCMD) --fix

.PHONY: check-licenses
check-licenses:
	$(TEMPDIR)/bouncer check

.PHONY: validate-cyclonedx-schema
validate-cyclonedx-schema:
	cd schema/cyclonedx && make

.PHONY: unit
unit: fixtures ## Run unit tests (with coverage)
	$(call title,Running unit tests)
	go test -coverprofile $(COVER_REPORT) $(shell go list ./... | grep -v anchore/syft/test)
	@go tool cover -func $(COVER_REPORT) | grep total |  awk '{print substr($$3, 1, length($$3)-1)}' > $(COVER_TOTAL)
	@echo "Coverage: $$(cat $(COVER_TOTAL))"
	@if [ $$(echo "$$(cat $(COVER_TOTAL)) >= $(COVERAGE_THRESHOLD)" | bc -l) -ne 1 ]; then echo "$(RED)$(BOLD)Failed coverage quality gate (> $(COVERAGE_THRESHOLD)%)$(RESET)" && false; fi

.PHONY: integration
integration: ## Run integration tests
	$(call title,Running integration tests)

	go test -v ./test/integration


# note: this is used by CI to determine if the integration test fixture cache (docker image tars) should be busted
integration-fingerprint:
	find test/integration/test-fixtures/image-* -type f -exec md5sum {} + | awk '{print $1}' | sort | md5sum | tee test/integration/test-fixtures/cache.fingerprint && echo "$(INTEGRATION_CACHE_BUSTER)" >> test/integration/test-fixtures/cache.fingerprint

.PHONY: java-packages-fingerprint
java-packages-fingerprint:
	@cd syft/cataloger/java/test-fixtures/java-builds && \
	make packages.fingerprint

.PHONY: fixtures
fixtures:
	$(call title,Generating test fixtures)
	cd syft/cataloger/java/test-fixtures/java-builds && make

.PHONY: generate-json-schema
generate-json-schema:  ## Generate a new json schema
	cd schema/json && go run generate.go

.PHONY: clear-test-cache
clear-test-cache: ## Delete all test cache (built docker image tars)
	find . -type f -wholename "**/test-fixtures/cache/*.tar" -delete

.PHONY: build-mac
build-mac: ## Build binary for macOS
	$(call title,Building binary for macOS)

	@OS="darwin" && ARCH="amd64" && GOOS="$$OS" GOARCH="$$ARCH" CGO_ENABLED=0 \
	go build \
		-o "./$(DISTDIR)/syft_$${OS}_$${ARCH}/syft" \
		-ldflags "-w -s -extldflags '-static' \
		-X github.com/anchore/syft/internal/version.version=$(VERSION) \
		-X github.com/anchore/syft/internal/version.gitCommit=$(COMMIT) \
		-X github.com/anchore/syft/internal/version.buildDate=$(DATE) \
		-X github.com/anchore/syft/internal/version.gitTreeState=$(BUILD_GIT_TREE_STATE)"

.PHONY: build-linux
build-linux: ## Build binary for macOS
	$(call title,Building binary for Linux)

	@OS="linux" && ARCH="amd64" && GOOS="$$OS" GOARCH="$$ARCH" CGO_ENABLED=0 \
	go build \
		-o "./$(DISTDIR)/syft_$${OS}_$${ARCH}/syft" \
		-ldflags "-w -s -extldflags '-static' \
		-X github.com/anchore/syft/internal/version.version=$(VERSION) \
		-X github.com/anchore/syft/internal/version.gitCommit=$(COMMIT) \
		-X github.com/anchore/syft/internal/version.buildDate=$(DATE) \
		-X github.com/anchore/syft/internal/version.gitTreeState=$(BUILD_GIT_TREE_STATE)"

.PHONY: build
build: build-mac build-linux

$(SNAPSHOTDIR): ## Build snapshot release binaries and packages
	$(call title,Building snapshot artifacts)
	# create a config with the dist dir overridden
	echo "dist: $(SNAPSHOTDIR)" > $(TEMPDIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMPDIR)/goreleaser.yaml

	# build release snapshots
	BUILD_GIT_TREE_STATE=$(GITTREESTATE) \
	$(TEMPDIR)/goreleaser release --skip-publish --rm-dist --snapshot --config $(TEMPDIR)/goreleaser.yaml

# note: we cannot clean the snapshot directory since the pipeline builds the snapshot separately
.PHONY: acceptance-mac
acceptance-mac: $(SNAPSHOTDIR) ## Run acceptance tests on build snapshot binaries and packages (Mac)
	$(call title,Running acceptance test: Run on Mac)
	$(ACC_DIR)/mac.sh \
			$(SNAPSHOTDIR) \
			$(ACC_DIR) \
			$(ACC_TEST_IMAGE) \
			$(RESULTSDIR)

# note: we cannot clean the snapshot directory since the pipeline builds the snapshot separately
.PHONY: acceptance-linux
acceptance-linux: acceptance-test-deb-package-install acceptance-test-rpm-package-install ## Run acceptance tests on build snapshot binaries and packages (Linux)

# note: this is used by CI to determine if the inline-scan report cache should be busted for the inline-compare tests
.PHONY: compare-fingerprint
compare-fingerprint:
	find test/inline-compare/* -type f -exec md5sum {} + | grep -v '\-reports' | grep -v 'fingerprint' | awk '{print $1}' | sort | md5sum | tee test/inline-compare/inline-compare.fingerprint && echo "$(COMPARE_CACHE_BUSTER)" >> test/inline-compare/inline-compare.fingerprint

.PHONY: compare-snapshot
compare-snapshot: $(SNAPSHOTDIR) ## Compare the reports of a run of a snapshot build of syft against inline-scan
	chmod 755 $(SNAPSHOT_CMD)
	@cd test/inline-compare && SYFT_CMD=$(SNAPSHOT_CMD) make

.PHONY: compare
compare:  ## Compare the reports of a run of a main-branch build of syft against inline-scan
	@cd test/inline-compare && make

.PHONY: acceptance-test-deb-package-install
acceptance-test-deb-package-install: $(SNAPSHOTDIR)
	$(call title,Running acceptance test: DEB install)
	$(ACC_DIR)/deb.sh \
			$(SNAPSHOTDIR) \
			$(ACC_DIR) \
			$(ACC_TEST_IMAGE) \
			$(RESULTSDIR)

.PHONY: acceptance-test-rpm-package-install
acceptance-test-rpm-package-install: $(SNAPSHOTDIR)
	$(call title,Running acceptance test: RPM install)
	$(ACC_DIR)/rpm.sh \
			$(SNAPSHOTDIR) \
			$(ACC_DIR) \
			$(ACC_TEST_IMAGE) \
			$(RESULTSDIR)

.PHONY: setup-macos-signing
setup-macos-signing: ## Prepare for macOS-specific signing process
	$(call title,Preparing macOS environment for code signing)

	@.github/scripts/mac-prepare-for-signing.sh

.PHONY: package-mac
package-mac: setup-macos-signing bootstrap-ci-mac ## Create signed and notarized release assets for macOS
	$(call title,Creating packaging for macOS -- signed and notarized)

	# Create signed and notarized assets
	@gon "./gon.hcl"

	# Update asset names. This won't be necessary once Gon supports variable injection.
	@ORIGINAL_NAME="$(DISTDIR)/output" && NEW_NAME="$(DISTDIR)/syft_$(VERSION)_darwin_amd64" && \
		mv -v "$${ORIGINAL_NAME}.dmg" "$${NEW_NAME}.dmg" && \
		mv -v "$${ORIGINAL_NAME}.zip" "$${NEW_NAME}.zip"

.PHONY: package-linux
.SILENT: package-linux
package-linux: bootstrap-ci-linux
	$(call title,Creating packaging for Linux)

	# Produce .tar.gz
	SYFT_PATH=$(DISTDIR)/syft_linux_amd64/syft && \
		tar -cvzf $(DISTDIR)/syft_$(VERSION)_linux_amd64.tar.gz "$$SYFT_PATH" "./README.md" "./LICENSE"

	# Produce .deb, .rpm
	for packager in "deb" "rpm"; do \
		$(TEMPDIR)/nfpm -f "./.nfpm.yaml" pkg --packager="$$packager" --target="$(DISTDIR)/syft_$(VERSION)_linux_amd64.$$packager"; \
	done

	# Produce integrity-check files (checksums.txt, checksums.txt.sig)
	pushd $(DISTDIR) && \
		CHECKSUMS_FILE="syft_$(VERSION)_checksums.txt" && \
		echo "" > "$$CHECKSUMS_FILE" && \
		for file in ./*linux*.*; do \
			openssl dgst -sha256 "$$file" >> "$$CHECKSUMS_FILE"; \
		done && \
		gpg --detach-sign "$$CHECKSUMS_FILE" && \
	popd

.PHONY: package
package: package-mac package-linux

.PHONY: changlog-release
changelog-release: bootstrap-ci-linux
	@echo "Last tag: $(SECOND_TO_LAST_TAG)"
	@echo "Current tag: $(VERSION_TAG)"
	@github_changelog_generator \
		--user anchore \
		--project $(BIN) \
		-t ${GITHUB_TOKEN} \
		--exclude-labels 'duplicate,question,invalid,wontfix,size:small,size:medium,size:large,size:x-large' \
		--no-pr-wo-labels \
		--no-issues-wo-labels \
		--since-tag $(SECOND_TO_LAST_TAG)

	@printf '\n$(BOLD)$(CYAN)Release $(VERSION_TAG) Changelog$(RESET)\n\n'
	@cat CHANGELOG.md

.PHONY: changelog-unreleased
changelog-unreleased: ## show the current changelog that will be produced on the next release (note: requires GITHUB_TOKEN set)
	@docker run -it --rm \
		-v "$(shell pwd)":/usr/local/src/your-app \
		ferrarimarco/github-changelog-generator \
		--user anchore \
		--project $(BIN) \
		-t ${GITHUB_TOKEN} \
		--exclude-labels 'duplicate,question,invalid,wontfix,size:small,size:medium,size:large,size:x-large' \
		--since-tag $(LAST_TAG)

	@printf '\n$(BOLD)$(CYAN)Unreleased Changes (closed PRs and issues will not be in the final changelog)$(RESET)\n'

	@docker run -it --rm \
		-v $(shell pwd)/CHANGELOG.md:/CHANGELOG.md \
		rawkode/mdv \
			-t 748.5989 \
			/CHANGELOG.md

.PHONY: homebrew-formula-generate
.SILENT: homebrew-formula-generate
homebrew-formula-generate:
	$(call title,Generating homebrew formula)
	# dependencies: curl, jq, openssl

	RELEASE_URL="https://api.github.com/repos/anchore/$(BIN)/releases/tags/$(VERSION_TAG)" && \
	echo "Using release: $${RELEASE_URL}" && \
	curl -sSL "$${RELEASE_URL}" > "$(TEMPDIR)/release.json"

	export DARWIN_AMD64_ASSET_URL=$(call asset_url,"$(TEMPDIR)/release.json","darwin_amd64.zip") && \
	curl -sSL "$${DARWIN_AMD64_ASSET_URL}" > "$(TEMPDIR)/darwin_amd64_asset" && \
	export DARWIN_AMD64_ASSET_SHA256=$(call sha256,"$(TEMPDIR)/darwin_amd64_asset") && \
	\
	export LINUX_AMD64_ASSET_URL=$(call asset_url,"$(TEMPDIR)/release.json","linux_amd64.tar.gz") && \
	curl -sSL "$${LINUX_AMD64_ASSET_URL}" > "$(TEMPDIR)/linux_amd64_asset" && \
	export LINUX_AMD64_ASSET_SHA256=$(call sha256,"$(TEMPDIR)/linux_amd64_asset") && \
	\
	export VERSION=$(call get_version_from_version_tag,$(VERSION_TAG)) && \
	\
	cat "./.homebrew-formula-template.rb" | \
		envsubst > "$(HOMEBREW_FORMULA_FILE)"

	echo "Generated $(HOMEBREW_FORMULA_FILE):" && \
	cat $(HOMEBREW_FORMULA_FILE)

.PHONY: homebrew-formula-test
.SILENT: homebrew-formula-test
homebrew-formula-test: bootstrap
	$(call title,Testing homebrew formula)

	echo "Cleaning up any versions of $(BIN) previously installed by $(BREW_CMD)"
	$(BREW_CMD) uninstall --force "$(HOMEBREW_FORMULA_FILE)"

	echo "Testing homebrew installation using formula"
	$(BREW_CMD) install --formula "$(HOMEBREW_FORMULA_FILE)"

	INSTALLED_BIN="$(BREW_BIN_DIR)/$(BIN)" && \
	echo "Now running '$${INSTALLED_BIN} version':" && \
	"$${INSTALLED_BIN}" version

.PHONY: homebrew-formula-publish
.SILENT: homebrew-formula-publish
homebrew-formula-publish:
	$(call title,Publishing homebrew formula)

	FORMULA_FILE="$$(realpath $(HOMEBREW_FORMULA_FILE))" && \
	\
	pushd "$(TEMPDIR)" && \
		rm -rfv "./homebrew-syft" && \
		gh repo clone anchore/homebrew-syft && \
		\
		pushd "homebrew-syft" && \
			cp -vf "$${FORMULA_FILE}" "./$(BIN).rb" && \
			git commit -am "Brew formula update for $(BIN) version $(VERSION_TAG)" && \
			git push && \
		popd && \
	popd

.PHONY: version-check-update
.SILENT: version-check-update
version-check-update:
	$(call title,Updating version check)

	# upload the version file that supports the application version update check (excluding pre-releases)
	.github/scripts/update-version-file.sh "$(DISTDIR)" "$(VERSION_TAG)"

.PHONY: container-image-build
.SILENT: container-image-build
container-image-build:
	$(call title,Building and tagging container image for $(BIN))

	tags=( \
		"-t $(CONTAINER_IMAGE_TAG_MAJOR)" \
		"-t $(CONTAINER_IMAGE_TAG_MINOR)" \
		"-t $(CONTAINER_IMAGE_TAG_PATCH)" \
		"-t $(CONTAINER_IMAGE_TAG_LATEST)" \
	) && \
	DOCKER_BUILDKIT=1 docker build --no-cache $${tags[@]} -f "./Dockerfile" .
	# Using buildkit due to https://github.com/moby/moby/issues/37965

.PHONY: container-image-test
.SILENT: container-image-test
container-image-test:
	$(call title,Testing container image tags)

	tags=( \
		"$(CONTAINER_IMAGE_TAG_MAJOR)" \
		"$(CONTAINER_IMAGE_TAG_MINOR)" \
		"$(CONTAINER_IMAGE_TAG_PATCH)" \
		"$(CONTAINER_IMAGE_TAG_LATEST)" \
	) && \
	for tag in $${tags[@]}; do \
		echo "—— testing $${tag}..." && \
		docker run --rm "$${tag}" version; \
	done

.PHONY: container-image-push
.SILENT: container-image-push
container-image-push:
	$(call title,Pushing container image tags)

	tags=( \
		"$(CONTAINER_IMAGE_TAG_MAJOR)" \
		"$(CONTAINER_IMAGE_TAG_MINOR)" \
		"$(CONTAINER_IMAGE_TAG_PATCH)" \
		"$(CONTAINER_IMAGE_TAG_LATEST)" \
	) && \
    for tag in $${tags[@]}; do \
		docker push "$${tag}"; \
    done

.PHONY: clean
clean: clean-dist clean-snapshot ## Remove previous builds and result reports
	rm -rf $(RESULTSDIR)/*

.PHONY: clean-snapshot
clean-snapshot:
	rm -rf $(SNAPSHOTDIR) $(TEMPDIR)/goreleaser.yaml

.PHONY: clean-dist
clean-dist:
	rm -rf $(DISTDIR) $(TEMPDIR)/goreleaser.yaml
