#!/usr/bin/env bash

cd "$(dirname "$0")"
# Run with debug logging enabled
mojo -I ../../src/ -D LOG_LEVEL=DEBUG server.mojo
