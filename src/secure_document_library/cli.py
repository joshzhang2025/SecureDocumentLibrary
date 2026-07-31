from __future__ import annotations

import argparse
import json
from pathlib import Path

from .library import build, retrieve, search

def main() -> None:
    parser = argparse.ArgumentParser(prog="secure-library")
    commands = parser.add_subparsers(dest="command", required=True)
    build_command = commands.add_parser("build"); build_command.add_argument("--source-root", required=True, type=Path); build_command.add_argument("--output", required=True, type=Path)
    search_command = commands.add_parser("search"); search_command.add_argument("query"); search_command.add_argument("--index", required=True, type=Path); search_command.add_argument("--authorized-source", action="append", default=[])
    get_command = commands.add_parser("retrieve"); get_command.add_argument("chunk_id"); get_command.add_argument("--index", required=True, type=Path); get_command.add_argument("--authorized-source", action="append", default=[])
    args = parser.parse_args()
    if args.command == "build": print(build(args.source_root, args.output))
    elif args.command == "search": print(json.dumps(search(args.index, args.query, set(args.authorized_source)), ensure_ascii=False, indent=2))
    else: print(retrieve(args.index, args.chunk_id, set(args.authorized_source)))
