"""Copy this file and implement the challenge's exact local scoring path."""

import json
import sys


def score(value):
    raise NotImplementedError('connect preprocessing, model inference and the exact scored output boundary')


if __name__ == '__main__':
    candidate = json.load(sys.stdin)
    print(json.dumps(str(score(candidate))))
