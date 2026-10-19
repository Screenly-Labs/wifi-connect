#!/bin/sh
# Print the crate version from Cargo.toml.
#
# Cargo.toml is the single source of truth for this project's version:
# the binary reports it through --version, the release tag is it with a
# `v` in front, and the container tags are derived from the tag. This
# script exists so the places that need it outside cargo — the snap
# build and the release workflow's tag guard — cannot drift from each
# other by having two copies of the same regex.
#
# Deliberately not `cargo metadata`/`cargo pkgid`: this runs inside
# snapcraft's build instance, which has no Rust toolchain at all (the
# snap packages a binary `cross` already built elsewhere), and pulling
# one in to read a string would be absurd.
set -eu

root="$(dirname "$0")/.."
version="$(
    sed -n '/^\[package\]/,/^\[/{s/^version = "\(.*\)"/\1/p;}' \
        "${root}/Cargo.toml"
)"

if [ -z "${version}" ]; then
    echo "could not read the package version from ${root}/Cargo.toml" >&2
    exit 1
fi

printf '%s\n' "${version}"
