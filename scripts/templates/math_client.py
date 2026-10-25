#!/usr/bin/env python3
"""Solve a synthetic timed arithmetic protocol over one pwntools connection.

Server: Q 1: (2 + 3) * 4\n   Client: 20\n
Server: Q 2: 12 / 3\n        Client: 4\n
Server: DONE practice-complete\n

Copy and edit QUESTION, the completion condition and answer formatting for the
actual challenge. IDs must start at 1 and increase by one. Only integer literals,
parentheses, unary +/-, + - * // % and exact integer / are supported. // and % use
Python's semantics (floor division). No powers, names, function calls or eval.
--budget covers connection and all questions; completion must arrive within it.
"""
import argparse
import ast
import math
import operator
import re
import sys
import time


QUESTION = re.compile(rb"Q ([1-9][0-9]{0,5}): (.+)\n")
MAX_LINE = 1024
MAX_EXPRESSION = 512
MAX_INTEGER = 10 ** 30
OPERATORS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
             ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod}


def solve(expression):
    """Evaluate a small, bounded integer expression without executing code."""
    if len(expression) > MAX_EXPRESSION:
        raise ValueError("expression exceeds 512 characters")
    try:
        tree = ast.parse(expression, mode="eval")
    except (SyntaxError, RecursionError) as error:
        raise ValueError("invalid expression") from error
    if sum(1 for _ in ast.walk(tree)) > 128:
        raise ValueError("expression exceeds 128 AST nodes")

    def visit(node):
        if isinstance(node, ast.Constant) and type(node.value) is int:
            value = node.value
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
            value = visit(node.operand)
            if isinstance(node.op, ast.USub):
                value = -value
        elif isinstance(node, ast.BinOp) and type(node.op) in (*OPERATORS, ast.Div):
            left, right = visit(node.left), visit(node.right)
            if isinstance(node.op, ast.Div):
                value, remainder = divmod(left, right)
                if remainder:
                    raise ValueError("/ requires an exact integer result")
            else:
                value = OPERATORS[type(node.op)](left, right)
        else:
            raise ValueError("unsupported arithmetic syntax")
        if abs(value) > MAX_INTEGER:
            raise ValueError("integer magnitude exceeds 10**30")
        return value

    return visit(tree.body)


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError("total time budget expired")
    return seconds


def read_line(tube, deadline):
    data = bytearray()
    while len(data) < MAX_LINE:
        chunk = tube.recv(1, timeout=remaining(deadline))
        if not chunk:
            raise TimeoutError("waiting for a complete protocol line")
        data.extend(chunk)
        if chunk == b"\n":
            return bytes(data)
    raise ValueError("protocol line exceeds 1024 bytes")


def exchange(tube, deadline, max_questions):
    answered = 0
    while True:
        line = read_line(tube, deadline)
        if line.startswith(b"DONE ") and answered:
            print(f"Answered {answered}; completion: {line.rstrip()!r}")
            return
        match = QUESTION.fullmatch(line)
        if not match:
            raise ValueError(f"unexpected protocol line: {line!r}")
        if answered >= max_questions:
            raise ValueError("question limit exceeded; expected DONE")
        if int(match[1]) != answered + 1:
            raise ValueError("question IDs must start at 1 and increase by one")
        answer = solve(match[2].decode("ascii"))
        tube.settimeout(remaining(deadline))
        tube.sendline(str(answer).encode("ascii"))
        answered += 1


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--local", nargs="+", metavar="COMMAND", help="local command and arguments, e.g. python3 math_demo.py")
    target.add_argument("--remote", nargs=2, metavar=("HOST", "PORT"))
    parser.add_argument("--budget", type=float, default=60, help="total seconds (default: 60)")
    parser.add_argument("--max-questions", type=int, default=100)
    args = parser.parse_args()
    if not math.isfinite(args.budget) or args.budget <= 0:
        parser.error("--budget must be finite and positive")
    if not 1 <= args.max_questions <= 999999:
        parser.error("--max-questions must be from 1 to 999999")
    if args.remote:
        try:
            port = int(args.remote[1])
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            parser.error("PORT must be an integer from 1 to 65535")
    try:
        from pwn import context, process, remote
        from pwnlib.exception import PwnlibException
    except ImportError:
        parser.error(f"pwntools is unavailable for {sys.executable}; use an interpreter with a working pwntools installation")
    context.log_level = "error"
    deadline = time.monotonic() + args.budget
    try:
        tube = (process(args.local, timeout=remaining(deadline))
                if args.local else remote(args.remote[0], port, timeout=remaining(deadline)))
        with tube:
            exchange(tube, deadline, args.max_questions)
        return 0
    except (EOFError, OSError, TimeoutError, ValueError, ArithmeticError, PwnlibException) as error:
        print(f"Failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
