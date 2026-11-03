import base64
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
import uuid

BURSAR_URL = os.environ.get("BURSAR_URL", "http://127.0.0.1:8402")
BURSAR_TOKEN = os.environ.get("BURSAR_TOKEN_NANOCODE", "")

TOOL_SPEC = {
    "name": "pay",
    "description": (
        "Fetch a URL that may require payment. If the server answers HTTP 402, "
        "the payment is sent to the local bursar daemon, which checks it against "
        "the spending policy and signs it; the request is then retried with the "
        "payment attached. Returns the final status, headers and body."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "method": {"type": "string", "default": "GET"},
            "body": {"type": "string"},
        },
        "required": ["url"],
    },
}


class PaymentDenied(Exception):
    pass


def _http(method, url, body=None, headers=None, timeout=30):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return res.status, res.headers, res.read()
    except urllib.error.HTTPError as err:
        return err.code, err.headers, err.read()


def _header(headers, name):
    return headers.get(name) if headers is not None else None


def resource_binding(method, url, body):
    body_sha = hashlib.sha256(body or b"").hexdigest()
    digest = hashlib.sha256(f"{method.upper()} {url}\n{body_sha}".encode()).hexdigest()
    return {"method": method.upper(), "url": url, "bodySha256": body_sha}, digest


def _bursar_post(path, request):
    status, _, data = _http(
        "POST",
        f"{BURSAR_URL}{path}",
        json.dumps(request).encode(),
        {"Authorization": f"Bearer {BURSAR_TOKEN}", "Content-Type": "application/json"},
    )
    try:
        return json.loads(data)
    except ValueError:
        raise PaymentDenied(f"bursar returned HTTP {status}")


def _payment_request(headers, data):
    required = _header(headers, "PAYMENT-REQUIRED")
    if required:
        return "x402", {"paymentRequired": json.loads(base64.b64decode(required))}
    challenges = [c for c in (headers.get_all("WWW-Authenticate") or []) if "payment" in c.lower()]
    if challenges:
        return "mpp", {"challenge": challenges}
    return "x402", {"paymentRequired": json.loads(data)}


def _bursar_sign(request):
    return _bursar_post("/v1/sign", request)


def open_task(budget_usd, ttl_seconds=3600, label=""):
    result = _bursar_post("/v1/tasks", {"budgetUsd": str(budget_usd), "ttlSeconds": ttl_seconds, "label": label})
    if "taskId" not in result:
        raise PaymentDenied(result.get("error") or json.dumps(result))
    return result["taskId"]


def pay(url, method="GET", body=None, headers=None, approval_wait_seconds=300, task_id=None):
    raw_body = body.encode() if isinstance(body, str) else body
    status, res_headers, data = _http(method, url, raw_body, headers)
    if status != 402:
        return status, res_headers, data

    protocol, payload = _payment_request(res_headers, data)
    resource, resource_hash = resource_binding(method, url, raw_body)
    request = {
        "protocol": protocol,
        "payload": payload,
        "idempotencyKey": f"nanocode-{uuid.uuid4()}",
        "resource": resource,
        "resourceHash": resource_hash,
    }
    if task_id:
        request["taskId"] = task_id

    deadline = time.monotonic() + approval_wait_seconds
    while True:
        result = _bursar_sign(request)
        if result.get("status") == "signed":
            break
        if result.get("status") == "pending" and time.monotonic() < deadline:
            time.sleep(3)
            continue
        raise PaymentDenied(result.get("reason") or result.get("error") or json.dumps(result))

    retry_headers = dict(headers or {})
    header = result.get("header")
    if header:
        retry_headers[header["name"]] = header["value"]
    else:
        raise PaymentDenied("bursar signed but returned no payment header for this protocol")
    return _http(method, url, raw_body, retry_headers)


if __name__ == "__main__":
    import sys

    code, hdrs, content = pay(sys.argv[1], *(sys.argv[2:3] or ["GET"]))
    receipt = _header(hdrs, "PAYMENT-RESPONSE") or _header(hdrs, "X-PAYMENT-RESPONSE")
    print(code)
    if receipt:
        print("payment receipt:", receipt)
    print(content[:2000].decode(errors="replace"))
