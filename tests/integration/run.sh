#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
qualification_dir=$(mktemp -d "${TMPDIR:-/tmp}/betterproxy-qualification.XXXXXX")
trap 'rm -rf "$qualification_dir"' EXIT
go build -o "$qualification_dir/betterproxy" ./cmd/betterproxy
for mta in postfix exim sendmail; do
  docker build --build-arg "MTA=$mta" -t "betterproxy-mta:$mta" tests/integration/mta
  python3 tests/integration/mta.py --betterproxy "$qualification_dir/betterproxy" --mta "$mta"
done
docker build -f tests/integration/mta/Dockerfile.qmail -t betterproxy-mta:qmail tests/integration/mta
python3 tests/integration/mta.py --betterproxy "$qualification_dir/betterproxy" --mta qmail
python3 tests/integration/platform.py --betterproxy "$qualification_dir/betterproxy" --image "${MAILHUB_IMAGE:-mailhub:qualification-2.7}"
