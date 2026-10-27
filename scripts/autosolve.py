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
    web.add_argument('--request-file', help='private raw request for WEB02/03/05')
    web.add_argument('--scope-origin', required=True)
    web.add_argument('--budget', type=float, default=180)
    web.add_argument('--wordlist', help='private file of at most 32 explicit discovery words')
    web.add_argument('--kind', choices=('path', 'parameter', 'vhost'), default='path')
    web.add_argument('--lead-kind', choices=('traversal', 'template'),
                     help='run one selected WEB05 differential check')
    web.add_argument('--parameter', help='existing query parameter selected for WEB05')
    web.add_argument('--probe-value', help='one explicitly selected relative file path for traversal')
    web.add_argument('--expected', help='response marker for WEB05; 323 for template')
    web.add_argument('--syntax', choices=('braces', 'dollar'),
                     help='arithmetic template syntax for WEB05')
    web.add_argument('--sql-parameter', help='existing query/form parameter selected for WEB03')
    web.add_argument('--sql-test', action='store_true', help='opt in to bounded WEB03 test requests')
    web.add_argument('--sql-location', choices=('query', 'form'), default='query')
    web.add_argument('--sql-context', choices=('text', 'number'), default='text')
    web.add_argument('--sql-table', help='selected table for bounded WEB03 candidate comparison')
    web.add_argument('--sql-column', help='selected column for bounded WEB03 candidate comparison')
    web.add_argument('--sql-candidate', action='append', dest='sql_candidates',
                     help='selected value candidate; at most four')
    web.add_argument('--workflow-file', help='private two-role WEB08 workflow fixture')
    web.add_argument('--workflow-test', action='store_true',
                     help='opt in to replay only explicitly safe WEB08 fixture steps')
    web.add_argument('--max-requests', type=int, default=34)
    web.add_argument('--rate', type=float, default=5, help='maximum requests per second, at most 20')
    web.add_argument('--runs-root', help='directory for private run records')
    service = commands.add_parser('service', help='analyze an explicitly scoped service')
    service.add_argument('--host', required=True)
    endpoints = service.add_mutually_exclusive_group(required=True)
    endpoints.add_argument('--port', type=int)
    endpoints.add_argument('--ports')
    service.add_argument('--protocol')
    service.add_argument('--enumerate', action='store_true')
    service.add_argument('--budget', type=float, default=120)
    service.add_argument('--runs-root', help='directory for private run records')
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
        if args.command in ('resume', 'report'):
            manifest = json.loads((Path(args.run) / 'manifest.json').read_text())
            if not isinstance(manifest, dict):
                raise core.InvalidInput('run manifest must be a JSON object')
        if args.command == 'analyze':
            run, status = core.analyze(args.path, category=args.category, budget=args.budget,
                                       hints_path=args.hints, runs_root=args.runs_root,
                                       execute_local=args.execute_local)
            result = {'status': status, 'run': str(run), 'report': str(run / 'report.md')}
            code = 3 if status == 'partial' else 0
        elif args.command == 'resume':
            if manifest.get('category') == 'ai_chatbot':
                from autosolve_lib.profiles import chatbot as chatbot_module
                run, status = chatbot_module.resume(args.run, budget=args.budget,
                                                     protocol_path=args.protocol,
                                                     max_requests=args.max_requests,
                                                     max_prompts=args.max_prompts)
            elif manifest.get('run_type') == 'service':
                from autosolve_lib import service as service_module
                run, status = service_module.resume(args.run)
            elif manifest.get('run_type') == 'service_inventory':
                from autosolve_lib import service_inventory as inventory_module
                run, status = inventory_module.resume(args.run)
            elif manifest.get('run_type') in ('web_discovery', 'web_sql', 'web_leads',
                                               'web_workflow'):
                from autosolve_lib import web as web_module
                run, status = web_module.resume(args.run)
            else:
                run, status = core.resume(args.run, budget=args.budget, hints_path=args.hints)
            result = {'status': status, 'run': str(run), 'report': str(run / 'report.md')}
            code = 3 if status == 'partial' else 0
        elif args.command == 'report':
            if manifest.get('category') == 'ai_chatbot':
                from autosolve_lib.profiles import chatbot as chatbot_module
                path = chatbot_module.report(args.run)
            elif manifest.get('run_type') == 'service':
                from autosolve_lib import service as service_module
                path = service_module.report(args.run)
            elif manifest.get('run_type') == 'service_inventory':
                from autosolve_lib import service_inventory as inventory_module
                path = inventory_module.report(args.run)
            elif manifest.get('run_type') in ('web_discovery', 'web_sql', 'web_leads',
                                               'web_workflow'):
                from autosolve_lib import web as web_module
                path = web_module.report(args.run)
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
        elif args.command == 'web':
            from autosolve_lib import web as web_module
            run, status = web_module.start(args.request_file, args.scope_origin, args.budget,
                                           args.wordlist, args.kind, args.max_requests,
                                           args.rate, args.runs_root, lead_kind=args.lead_kind,
                                           parameter=args.parameter, probe_value=args.probe_value,
                                           expected=args.expected, syntax=args.syntax,
                                           sql_parameter=args.sql_parameter,
                                           sql_test=args.sql_test, sql_location=args.sql_location,
                                           sql_context=args.sql_context, sql_table=args.sql_table,
                                           sql_column=args.sql_column,
                                           sql_candidates=args.sql_candidates,
                                           workflow_path=args.workflow_file,
                                           workflow_test=args.workflow_test)
            result = {'status': status, 'run': str(run), 'report': str(run / 'report.md')}
            code = 3
        elif args.command == 'service':
            if args.enumerate:
                if args.ports is None:
                    raise ValueError('service --enumerate requires --ports')
                from autosolve_lib import service_inventory as inventory_module
                run, status = inventory_module.start(args.host, args.ports,
                                                     args.budget, args.runs_root,
                                                     protocol_path=args.protocol)
            else:
                if args.port is None:
                    raise ValueError('service framing requires --port and --protocol')
                from autosolve_lib import service as service_module
                run, status = service_module.start(args.host, args.port, args.protocol,
                                                   args.budget, args.runs_root)
            result = {'status': status, 'run': str(run), 'report': str(run / 'report.md')}
            code = 3
        else:
            result = {'status': 'unsupported', 'reason': f'{args.command} adapter is not implemented',
                      'scope': {'host': args.host, 'port': args.port, 'ports': args.ports}}
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
