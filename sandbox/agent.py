import importlib.util
import json
import os
import sys
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MERCHANT = os.environ["MERCHANT_URL"]
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
MERCHANT_EVM = "0x5afe00000000000000000000000000000000cafe"


def load_tool(token):
    os.environ["BURSAR_TOKEN_NANOCODE"] = token
    spec = importlib.util.spec_from_file_location(f"tool_{uuid.uuid4().hex}", os.path.join(ROOT, "examples", "nanocode-tool.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


nanocode = load_tool(os.environ["TOKEN_NANOCODE"])
researcher = load_tool(os.environ["TOKEN_RESEARCHER"])

results = []


def outcome(tool, fn):
    try:
        status, _, data = fn()
        body = json.loads(data or b"{}")
        if status == 200:
            return f"paid {body.get('paid')}"
        return f"http {status}: {body.get('error')}"
    except tool.PaymentDenied as e:
        return f"denied: {e}"


def check(name, expected, got):
    ok = expected in got
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name:<52} {got}" + ("" if ok else f"   (expected: {expected})"), flush=True)


def pay(tool, path, **kw):
    return outcome(tool, lambda: tool.pay(f"{MERCHANT}{path}", **kw))


def word(hex_value):
    return hex_value.lower().replace("0x", "").rjust(64, "0")


def raw_evm(tool, selector, key):
    data = f"0x{selector}{word(MERCHANT_EVM)}{word(hex(150000))}"
    r = tool._bursar_sign({
        "protocol": "evm",
        "idempotencyKey": key,
        "payload": {"chainId": 8453, "to": USDC_BASE, "data": data, "value": "0", "nonce": 0,
                    "gasLimit": 60000, "maxFeePerGas": "1000000000", "maxPriorityFeePerGas": "1000000"},
    })
    return r.get("status") if r.get("status") == "signed" else f"denied: {r.get('reason')}"


print("== happy path ==")
check("x402 v2 on Base, $0.10", "paid 100000", pay(nanocode, "/x402/data"))
check("same endpoint again, new payment", "paid 100000", pay(nanocode, "/x402/data"))
check("x402 v1 (X-PAYMENT), $0.05", "paid 50000", pay(nanocode, "/x402/v1/quote"))
check("x402 on Solana, $0.20, blockhash from RPC", "paid 200000", pay(nanocode, "/x402/solana/tile"))

print("\n== policy says no ==")
check("$2.00 GPU hour over per_tx", "denied: per_tx_limit", pay(nanocode, "/x402/gpu-hour"))
check("payTo is not allowlisted", "denied: recipient_not_allowed", pay(nanocode, "/x402/phish"))
check("label says $0.01, signed amount is $0.90", "denied: display_amount_mismatch", pay(nanocode, "/x402/cheap-label"))
check("402 charges for a different resource", "denied: resource_hash_mismatch", pay(nanocode, "/x402/bait"))
check("MPP / Tempo, server pays fees", "denied: signer_not_implemented", pay(nanocode, "/mpp/chat"))
check("MPP / Tempo, wallet would pay fees", "denied: mpp_client_fees_not_allowed", pay(nanocode, "/mpp/chat-client-fees"))

print("\n== human in the loop (the sandbox plays the human) ==")
check("$0.70 report, pending, human approves", "paid 700000", pay(nanocode, "/x402/report", approval_wait_seconds=25))
check("$0.80 report, pending, human denies", "denied: approval_denied", pay(nanocode, "/x402/report-premium", approval_wait_seconds=25))

print("\n== task budget ($0.50 task, $0.10 calls) ==")
task = nanocode.open_task("0.50", 600, "sandbox: summarise market")
task_runs = [pay(nanocode, "/x402/data", task_id=task) for _ in range(6)]
check("first five calls fit the task", "paid", " ".join(task_runs[:5]) if all(r.startswith("paid") for r in task_runs[:5]) else str(task_runs[:5]))
check("sixth call exceeds the task", "denied: task_budget_limit", task_runs[5])
try:
    nanocode.open_task("10.00", 600, "too big")
    check("task above per_task.max_usd is refused", "refused", "opened")
except nanocode.PaymentDenied as e:
    check("task above per_task.max_usd is refused", "budgetUsd must be between", str(e))

print("\n== raw EVM transactions ==")
check("ERC-20 transfer to allowlisted merchant (simulated via RPC)", "signed", raw_evm(nanocode, "a9059cbb", f"evm-{uuid.uuid4()}"))
check("approve() is never signed", "denied: selector_not_allowed", raw_evm(nanocode, "095ea7b3", f"evm-{uuid.uuid4()}"))

print("\n== second agent on the same wallet ==")
paid = 0
last = ""
for _ in range(60):
    last = pay(researcher, "/x402/data")
    if not last.startswith("paid"):
        break
    paid += 1
check(f"researcher paid {paid} x $0.10, then wallet cap", "denied: wallet_per_day_limit", last)

print(f"\n{sum(results)}/{len(results)} scenarios behaved as expected")
sys.exit(0 if all(results) else 1)
