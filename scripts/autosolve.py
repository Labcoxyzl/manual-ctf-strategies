#!/usr/bin/env python3
"""Bounded local CTF artifact analysis with explicit capability limits."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from autosolve_lib import core


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', action='store_true', help='emit a JSON result')
    commands = parser.add_subparsers(dest='command', required=True)
    analyze = commands.add_parser('analyze', help='analyze a local file or directory')
    analyze.add_argument('path')
    analyze.add_argument('--category', default='auto')
    analyze.add_argument('--budget', type=float, default=300)
    analyze.add_argument('--hints')
    analyze.add_argument('--runs-root', help='directory for private run records')
    analyze.add_argument('--execute-local', action='store_true', help='permit supported local execution adapters')
    resume = commands.add_parser('resume', help='resume a recorded run')
    resume.add_argument('run')
    resume.add_argument('--budget', type=float, default=300)
    resume.add_argument('--hints')
    resume.add_argument('--protocol', help='chatbot protocol file, if its original path moved')
    resume.add_argument('--max-requests', type=int, help='raise chatbot request ceiling on resume')
    resume.add_argument('--max-prompts', type=int, help='raise chatbot prompt ceiling on resume')
    report = commands.add_parser('report', help='render a run report')
    report.add_argument('run')
    capability = commands.add_parser('capabilities', help='show family implementation status')
    capability.add_argument('--category', default='auto')
    doctor = commands.add_parser('doctor', help='inspect local operation readiness')
    doctor.add_argument('--profiles', nargs='+', default=['all'])
    doctor.add_argument('--self-test', action='store_true')
    setup = commands.add_parser('setup', help='prepare implemented local operations without administrator rights')
    setup.add_argument('--profiles', nargs='+', default=['all'])
    web = commands.add_parser('web', help='analyze an explicitly scoped web request')
    web.add_argument('--request-file', required=True)
    web.add_argument('--scope-origin', required=True)
    web.add_argument('--budget', type=float, default=180)
    service = commands.add_parser('service', help='analyze an explicitly scoped service')
    service.add_argument('--host', required=True)
    endpoints = service.add_mutually_exclusive_group(required=True)
    endpoints.add_argument('--port', type=int)
    endpoints.add_argument('--ports')
    service.add_argument('--protocol')
    service.add_argument('--enumerate', action='store_true')
    service.add_argument('--budget', type=float, default=120)
    chatbot = commands.add_parser('chatbot', help='inspect and probe an authorized chatbot origin')
    chatbot.add_argument('--origin', required=True)
    chatbot.add_argument('--protocol', help='private JSON request/response shape and optional auth')
    chatbot.add_argument('--strategy', help='one selected chatbot playbook; see chatbot-strategies')
    chatbot.add_argument('--budget', type=float, required=True, help='overall seconds, at most 600')
    chatbot.add_argument('--max-requests', type=int, required=True)
    chatbot.add_argument('--max-prompts', type=int, default=6)
    chatbot.add_argument('--timeout', type=float, default=10)
    chatbot.add_argument('--runs-root')
    chatbot.add_argument('--dry-run', action='store_true')
    commands.add_parser('chatbot-strategies', help='list bounded chatbot playbooks and required parameters')
    args = parser.parse_args(argv)
    try:
        if args.command == 'analyze':
            run, status = core.analyze(args.path, category=args.category, budget=args.budget,
                                       hints_path=args.hints, runs_root=args.runs_root,
                                       execute_local=args.execute_local)
            result = {'status': status, 'run': str(run), 'report': str(run / 'report.md')}
            code = 3 if status == 'partial' else 0
        elif args.command == 'resume':
            manifest = json.loads((Path(args.run) / 'manifest.json').read_text())
            if manifest.get('category') == 'ai_chatbot':
                from autosolve_lib.profiles import chatbot as chatbot_module
                run, status = chatbot_module.resume(args.run, budget=args.budget,
                                                     protocol_path=args.protocol,
                                                     max_requests=args.max_requests,
                                                     max_prompts=args.max_prompts)
            else:
                run, status = core.resume(args.run, budget=args.budget, hints_path=args.hints)
            result = {'status': status, 'run': str(run), 'report': str(run / 'report.md')}
            code = 3 if status == 'partial' else 0
        elif args.command == 'report':
            manifest = json.loads((Path(args.run) / 'manifest.json').read_text())
            if manifest.get('category') == 'ai_chatbot':
                from autosolve_lib.profiles import chatbot as chatbot_module
                path = chatbot_module.report(args.run)
            else:
                path = core.report(args.run)
            result, code = {'status': 'complete', 'report': str(path)}, 0
        elif args.command == 'capabilities':
            result, code = {'status': 'complete', 'families': core.capabilities(args.category)}, 0
        elif args.command in ('doctor', 'setup'):
            from autosolve_lib import setup as setup_module
            result = (setup_module.doctor(args.profiles, args.self_test)
                      if args.command == 'doctor' else setup_module.setup(args.profiles))
            code = 0 if result['status'] == 'ready' else 3
        elif args.command == 'chatbot':
            from autosolve_lib.profiles import chatbot as chatbot_module
            run, status = chatbot_module.start(args.origin, args.protocol, args.budget,
                                               args.max_requests, args.max_prompts,
                                               args.timeout, args.runs_root, args.dry_run,
                                               strategy=args.strategy)
            result = {'status': status, 'run': str(run), 'report': str(run / 'report.md')}
            code = 3 if status == 'partial' else 0
        elif args.command == 'chatbot-strategies':
            from autosolve_lib.profiles.chatbot_strategies import listing
            result, code = {'status': 'complete', 'strategies': listing()}, 0
        else:
            result = {'status': 'unsupported', 'reason': f'{args.command} adapter is not implemented',
                      'scope': {'origin': args.scope_origin} if args.command == 'web'
                      else {'host': args.host, 'port': args.port, 'ports': args.ports}}
            code = 3
    except (core.InvalidInput, core.RunBusy, ValueError) as error:
        result, code = {'status': 'invalid_input', 'reason': str(error)}, 2
    except KeyboardInterrupt:
        result, code = {'status': 'interrupted'}, 130
    except OSError as error:
        result, code = {'status': 'failed', 'reason': f'{type(error).__name__}: {error.strerror}'}, 1
    if args.json:
        print(json.dumps(result, sort_keys=True))
    elif args.command == 'report' and code == 0 and manifest.get('category') != 'ai_chatbot':
        print(path.read_text(), end='')
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
