#!/bin/sh
# Print the crate version from Cargo.toml.
#
# Usage: version.sh            the crate version, e.g. 2026.9.0
#        version.sh --calver   the release version, e.g. 2026.09.0
#
# The two differ only in the month. Releases are CalVer YYYY.0M.MICRO,
# zero-padded like Anthias's, so tags, images, tarballs and the snap
# sort and read the same way across both projects. Cargo.toml cannot
# hold that form: Cargo requires strict semver, which forbids a leading
# zero, so the crate carries 2026.9.0 for the release tagged v2026.09.0.
# Pad here rather than keep a second copy of the version anywhere.
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

case "${1:-}" in
    '') form=crate ;;
    --calver) form=calver ;;
    *)
        echo "usage: $0 [--calver]" >&2
        exit 2
        ;;
esac

root="$(dirname "$0")/.."
version="$(
    sed -n '/^\[package\]/,/^\[/{s/^version = "\(.*\)"/\1/p;}' \
        "${root}/Cargo.toml"
)"

if [ -z "${version}" ]; then
    echo "could not read the package version from ${root}/Cargo.toml" >&2
    exit 1
fi

if [ "${form}" = calver ]; then
    version="$(printf '%s\n' "${version}" | sed 's/^\([0-9]\{4\}\)\.\([1-9]\)\./\1.0\2./')"
fi

printf '%s\n' "${version}"
