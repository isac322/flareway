#!/usr/bin/env python3

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def builder_image(dockerfile: Path) -> str:
    pattern = re.compile(r"^\s*ARG\s+GO_IMAGE=(\S+)\s*$")
    matches = [
        match.group(1)
        for line in dockerfile.read_text(encoding="utf-8").splitlines()
        if (match := pattern.match(line))
    ]
    if len(matches) != 1:
        raise ValueError(f"expected one GO_IMAGE default in {dockerfile}, found {len(matches)}")
    return matches[0]


def inspect_manifest(image: str, container_tool: str) -> dict:
    result = subprocess.run(
        [container_tool, "buildx", "imagetools", "inspect", "--raw", image],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def release_platforms(manifest: dict) -> list[str]:
    candidates = []
    if "manifests" in manifest:
        candidates = [entry.get("platform", {}) for entry in manifest["manifests"]]
    elif "os" in manifest and "architecture" in manifest:
        candidates = [manifest]

    platforms = set()
    for platform in candidates:
        os_name = platform.get("os")
        architecture = platform.get("architecture")
        if os_name != "linux" or not architecture or architecture == "unknown":
            continue
        variant = platform.get("variant")
        if architecture == "arm64" and variant in {"v8", "v8.0"}:
            variant = None
        value = f"{os_name}/{architecture}"
        if variant:
            value += f"/{variant}"
        platforms.add(value)

    if not platforms:
        raise ValueError("reference image exposes no Linux platforms")
    return sorted(platforms)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="List the Linux platforms published by Flareway's pinned Go builder image."
    )
    parser.add_argument("--dockerfile", type=Path, default=Path("Dockerfile"))
    parser.add_argument("--image", help="Inspect this image instead of Dockerfile's GO_IMAGE")
    parser.add_argument("--manifest", type=Path, help="Read an OCI manifest from a local file")
    parser.add_argument(
        "--container-tool", default=os.environ.get("CONTAINER_TOOL", "docker")
    )
    args = parser.parse_args()

    try:
        image = args.image or builder_image(args.dockerfile)
        if args.manifest:
            manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        else:
            manifest = inspect_manifest(image, args.container_tool)
        print(",".join(release_platforms(manifest)))
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or "").strip()
        message = detail or str(error)
        print(f"release platform discovery failed: {message}", file=sys.stderr)
        return 1
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"release platform discovery failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
