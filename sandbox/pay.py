import argparse
import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

parser = argparse.ArgumentParser(description="Play an agent that pays the sandbox merchant through bursar.")
parser.add_argument("path", nargs="?", help="merchant path, e.g. /x402/data")
parser.add_argument("--agent", default="nanocode", choices=["nanocode", "researcher"])
parser.add_argument("--task", help="task id to charge")
parser.add_argument("--open-task", metavar="USD", help="open a task with this budget first")
parser.add_argument("--ttl", type=int, default=3600)
parser.add_argument("--wait", type=int, default=300, help="seconds to wait for a human approval")
args = parser.parse_args()

os.environ["BURSAR_TOKEN_NANOCODE"] = os.environ[f"BURSAR_TOKEN_{args.agent.upper()}"]
spec = importlib.util.spec_from_file_location("bursar_tool", os.path.join(ROOT, "examples", "nanocode-tool.py"))
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

task = args.task
if args.open_task:
    try:
        task = tool.open_task(args.open_task, args.ttl, f"manual {args.agent}")
    except tool.PaymentDenied as e:
        sys.exit(f"task refused: {e}")
    print(f"task opened: {task}")

if not args.path:
    sys.exit(0)

try:
    status, headers, data = tool.pay(f"{os.environ['MERCHANT_URL']}{args.path}", approval_wait_seconds=args.wait, task_id=task)
except tool.PaymentDenied as e:
    sys.exit(f"denied by bursar: {e}")

print(f"merchant answered {status}")
try:
    print(json.dumps(json.loads(data), indent=2))
except ValueError:
    print(data.decode(errors="replace"))
