from __future__ import annotations

import argparse
import json
from pathlib import Path

from .build import build_staging
from .governance import AuthorizationContext, Intent, prepare_answer
from .library import retrieve, search
from .release import list_releases, publish, rollback, validate_release


def main() -> None:
    parser = argparse.ArgumentParser(prog="secure-library")
    commands = parser.add_subparsers(dest="command", required=True)
    build_command = commands.add_parser("build"); build_command.add_argument("--source-root", required=True, type=Path); build_command.add_argument("--index-root", required=True, type=Path); build_command.add_argument("--mode", choices=("full", "incremental"), default="full")
    validate_command = commands.add_parser("validate"); validate_command.add_argument("--staging", required=True, type=Path)
    publish_command = commands.add_parser("publish"); publish_command.add_argument("--staging", required=True, type=Path); publish_command.add_argument("--index-root", required=True, type=Path); publish_command.add_argument("--expected-build-id")
    search_command = commands.add_parser("search"); search_command.add_argument("query"); search_command.add_argument("--index-root", required=True, type=Path); search_command.add_argument("--authorized-source", action="append", default=[]); search_command.add_argument("--limit", type=int, default=100)
    get_command = commands.add_parser("retrieve"); get_command.add_argument("chunk_id"); get_command.add_argument("--index-root", required=True, type=Path); get_command.add_argument("--authorized-source", action="append", default=[])
    answer_command = commands.add_parser("answer"); answer_command.add_argument("question"); answer_command.add_argument("--index-root", required=True, type=Path); answer_command.add_argument("--authorized-source", action="append", default=[]); answer_command.add_argument("--intent", choices=("auto", "fact", "summary", "solution"), default="auto")
    list_command = commands.add_parser("list-releases"); list_command.add_argument("--index-root", required=True, type=Path)
    rollback_command = commands.add_parser("rollback"); rollback_command.add_argument("build_id"); rollback_command.add_argument("--index-root", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "build": print(build_staging(args.source_root, args.index_root, mode=args.mode))
    elif args.command == "validate": print(json.dumps(validate_release(args.staging), ensure_ascii=False, indent=2))
    elif args.command == "publish": print(publish(args.staging, args.index_root, expected_build_id=args.expected_build_id))
    elif args.command == "search": print(json.dumps(search(args.index_root, args.query, set(args.authorized_source), limit=args.limit), ensure_ascii=False, indent=2))
    elif args.command == "retrieve": print(retrieve(args.index_root, args.chunk_id, set(args.authorized_source)))
    elif args.command == "list-releases": print(json.dumps(list_releases(args.index_root)))
    elif args.command == "rollback": print(rollback(args.build_id, args.index_root))
    else:
        intent = {"auto": None, "fact": Intent.FACT_LOOKUP, "summary": Intent.SUMMARY, "solution": Intent.SOLUTION_DESIGN}[args.intent]
        context = AuthorizationContext(principal_id="cli", authorized_source_ids=frozenset(args.authorized_source), request_id="cli")
        print(json.dumps(prepare_answer(args.index_root, args.question, context, intent=intent), ensure_ascii=False, indent=2, default=str))
