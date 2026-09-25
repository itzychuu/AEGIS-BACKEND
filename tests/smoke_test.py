import urllib.request
import json
import time

def get(path):
    req = urllib.request.Request(f"http://127.0.0.1:8000{path}")
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode())

def post(path, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:8000{path}",
        data=data,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())

def run():
    print("=== AEGIS LIVE API SMOKE TEST ===")

    # 1. Health Endpoint
    h_status, h_data = get("/api/v1/health")
    print(f"1. GET /api/v1/health -> HTTP {h_status}: {h_data}")

    # 2. Readiness Endpoint
    r_status, r_data = get("/api/v1/ready")
    print(f"2. GET /api/v1/ready -> HTTP {r_status}: {r_data}")

    # 3. First Analysis (https://example.com)
    t0 = time.perf_counter()
    a1_status, a1_data = post("/api/v1/analyze", {"url": "https://example.com"})
    t1 = time.perf_counter()
    first_lat = (t1 - t0) * 1000
    print(f"3. POST /api/v1/analyze (First) -> HTTP {a1_status} ({first_lat:.2f}ms):")
    print(f"   classification={a1_data.get('classification')}, risk_score={a1_data.get('risk_score')}, cached={a1_data.get('cached')}")
    if a1_data.get("ai"):
        print(f"   ai_status={a1_data['ai'].get('status')}, ai_provider={a1_data['ai'].get('provider')}")

    # 4. Repeated Analysis (Cache Hit)
    t0 = time.perf_counter()
    a2_status, a2_data = post("/api/v1/analyze", {"url": "https://example.com"})
    t2 = time.perf_counter()
    cached_lat = (t2 - t0) * 1000
    print(f"4. POST /api/v1/analyze (Cached) -> HTTP {a2_status} ({cached_lat:.2f}ms):")
    print(f"   classification={a2_data.get('classification')}, risk_score={a2_data.get('risk_score')}, cached={a2_data.get('cached')}")

    # 5. Empty URL Validation
    v_status, v_data = post("/api/v1/analyze", {"url": ""})
    print(f"5. Empty URL -> HTTP {v_status}: {v_data}")

    # 6. SSRF Protection URL
    s_status, s_data = post("/api/v1/analyze", {"url": "http://169.254.169.254/latest/meta-data/"})
    print(f"6. SSRF IP -> HTTP {s_status}: classification={s_data.get('classification')}, risk_score={s_data.get('risk_score')}")

    print("=== SMOKE TEST COMPLETE ===")

if __name__ == "__main__":
    run()
