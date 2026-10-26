"""One-command, entirely local end-to-end demo of broken vs safe behavior."""
from __future__ import annotations
import json
import pathlib
import threading
from http.server import ThreadingHTTPServer
from .webhook_server import DemoState, make_handler
from replayproof.engine import execute
from replayproof.cli import markdown_report


def main():
    root=pathlib.Path(__file__).parents[1]
    target=root/'examples'/'staging.json'
    output=root/'demo_output'
    output.mkdir(exist_ok=True)
    config_template=json.loads(target.read_text())
    for mode in ('vulnerable','safe'):
        server=ThreadingHTTPServer(('127.0.0.1',0),make_handler(DemoState(mode=='safe')))
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            manifest=json.loads(json.dumps(config_template))
            for key in ('target','probe','reset'):
                manifest[key]=manifest[key].replace('8765',str(server.server_address[1]))
            report=execute(manifest)
            (output/f'{mode}.json').write_text(json.dumps(report,indent=2)+'\n')
            (output/f'{mode}.md').write_text(markdown_report(report))
            stats=report['summary']
            print(f"{mode}: PASS {stats['pass']} / FAIL {stats['fail']} / INCONCLUSIVE {stats['inconclusive']}")
        finally:
            server.shutdown();server.server_close();thread.join(timeout=2)
    print(f"Reports written to: {output}")


if __name__ == '__main__':
    main()
