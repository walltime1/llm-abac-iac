"""Phoenix GraphQL query helper for trace analysis."""

import json
import sys
import urllib.request


PHOENIX_URL = "http://localhost:6006/graphql"


def query(gql: str, variables: dict = None) -> dict:
    payload = {"query": gql}
    if variables:
        payload["variables"] = variables
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        PHOENIX_URL,
        data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def get_trace_spans(trace_id: str) -> list[dict]:
    """Get all spans for a trace, sorted by start time."""
    result = query("""
    query($traceId: String!) {
      getTraceByOtelId(traceId: $traceId) {
        traceId latencyMs numSpans
        spans(first: 200) {
          edges {
            node {
              name spanKind statusCode statusMessage
              latencyMs parentId spanId
              tokenCountPrompt tokenCountCompletion tokenCountTotal
              input { value }
              output { value }
              startTime
            }
          }
        }
      }
    }
    """, {"traceId": trace_id})
    trace = result.get("data", {}).get("getTraceByOtelId")
    if not trace:
        print(f"Trace {trace_id} not found")
        return []
    print(f"Trace: {trace['traceId']}, {trace['numSpans']} spans, {trace['latencyMs']/1000:.1f}s")
    spans = [e["node"] for e in trace["spans"]["edges"]]
    spans.sort(key=lambda s: s.get("startTime", ""))
    return spans


def print_trace_summary(trace_id: str):
    """Print a summary of LLM calls and code executions in a trace."""
    spans = get_trace_spans(trace_id)
    if not spans:
        return

    for s in spans:
        name = s["name"]
        kind = s["spanKind"]
        status = s["statusCode"]
        latency = s.get("latencyMs") or 0
        tok_in = s.get("tokenCountPrompt") or 0
        tok_out = s.get("tokenCountCompletion") or 0

        # Filter to interesting spans
        if name in ("RLM.forward", "Predict.forward", "ChatAdapter.__call__",
                     "JSONAdapter.__call__"):
            continue
        if kind == "LLM":
            print(f"  LLM  {latency/1000:6.1f}s  in={tok_in:>6d} out={tok_out:>5d}  {name}")
        elif "execute" in name.lower() or "code" in name.lower():
            output = s.get("output", {})
            out_val = output.get("value", "")[:150] if output else ""
            print(f"  EXEC {latency/1000:6.1f}s  {out_val}")
        elif status == "ERROR":
            msg = s.get("statusMessage", "")[:100]
            print(f"  ERR  {latency/1000:6.1f}s  {name}: {msg}")


def print_llm_io(trace_id: str, span_index: int = None):
    """Print full input/output for LLM spans."""
    spans = get_trace_spans(trace_id)
    llm_spans = [s for s in spans if s["spanKind"] == "LLM"]
    print(f"{len(llm_spans)} LLM calls total\n")

    for i, s in enumerate(llm_spans):
        if span_index is not None and i != span_index:
            continue
        tok_in = s.get("tokenCountPrompt") or 0
        tok_out = s.get("tokenCountCompletion") or 0
        latency = s.get("latencyMs") or 0
        print(f"=== LLM call #{i} ({latency/1000:.1f}s, {tok_in} in / {tok_out} out) ===")
        inp = s.get("input", {})
        out = s.get("output", {})
        if inp and inp.get("value"):
            # Truncate input to last 500 chars (the prompt is huge)
            val = inp["value"]
            if len(val) > 500:
                print(f"  INPUT: ...{val[-500:]}")
            else:
                print(f"  INPUT: {val}")
        if out and out.get("value"):
            print(f"  OUTPUT: {out['value'][:1000]}")
        print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python phoenix_query.py <trace_id> [detail|llm <index>]")
        sys.exit(1)

    trace_id = sys.argv[1]
    if len(sys.argv) >= 3 and sys.argv[2] == "detail":
        print_llm_io(trace_id)
    elif len(sys.argv) >= 4 and sys.argv[2] == "llm":
        print_llm_io(trace_id, int(sys.argv[3]))
    else:
        print_trace_summary(trace_id)
