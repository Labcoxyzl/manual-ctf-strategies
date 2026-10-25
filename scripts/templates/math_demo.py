#!/usr/bin/env python3
"""Harmless stdin/stdout practice server for math_client.py --local.

Asks 100 deterministic integer questions, checks every answer, then sends DONE.
This is a practice protocol, not a predictor of competition question formats.
"""
import sys


def main():
    for number in range(1, 101):
        print(f"Q {number}: ({number} + 2) * 3", flush=True)
        if sys.stdin.readline().strip() != str((number + 2) * 3):
            print(f"ERROR incorrect answer to question {number}", flush=True)
            return 1
    print("DONE practice-complete", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
