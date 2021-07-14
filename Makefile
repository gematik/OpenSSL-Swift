#
# Makefile
#

CIBUILD     ?= false
BUILD_TYPE  ?= Debug
PROJECT_DIR := $(PWD)

ifeq ($(CIBUILD), true)
  BUILD_TYPE = Release
endif

.PHONY: setup test build update lint format cibuild

setup:
	$(PROJECT_DIR)/scripts/setup ${BUILD_TYPE}

test:
	$(PROJECT_DIR)/scripts/test

build:
	$(PROJECT_DIR)/scripts/build ${BUILD_TYPE}

update:
	$(PROJECT_DIR)/scripts/update

lint:
	$(PROJECT_DIR)/scripts/lint

format:
	$(PROJECT_DIR)/scripts/format

cibuild:
	$(PROJECT_DIR)/scripts/cibuild ${BUILD_TYPE}
