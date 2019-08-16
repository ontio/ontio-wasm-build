#!/bin/bash
set -e
set -x

cargo build
cargo test 
