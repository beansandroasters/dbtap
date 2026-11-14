"""Match MySQL traffic and slow logs by Thread_id, SQL shape, values, and execution order."""
import collections
import difflib
import json
import statistics
import sys


def read(path):
    info, sessions = {}, collections.defaultdict(list)
    counts = collections.Counter()
    for line in open(path):
        e = json.loads(line)
        if e["type"] == "open":
            i = e["info"]
            info[i["conn"]] = i["server_session"]
        elif e["type"] == "unit":
            u = e["unit"]
            counts["units"] += 1
            cmd = u["req"][0] if u["req"] else None
            if not u["origin"] and cmd not in (3, 23):  # COM_QUERY / COM_STMT_EXECUTE
                counts["non_sql_commands"] += 1
                continue
            counts["sql_executions"] += 1
            key = (e["shape"].lower().rstrip(";").strip(), tuple(sorted(u["vals"])))
            sessions[info[u["conn"]]].append((key, u))
    return sessions, dict(counts)


def dist(v):
    if not v:
        return {"n": 0}
    v = sorted(v)
    return {"n": len(v), "min_ms": v[0], "p50_ms": v[round((len(v)-1)*.5)],
            "p95_ms": v[round((len(v)-1)*.95)], "max_ms": v[-1], "mean_ms": statistics.mean(v)}


w, wc = read(sys.argv[1])
l, lc = read(sys.argv[2])
missing, extra, starts, ends = [], [], [], []
matched = 0
for conn in sorted(w.keys() | l.keys()):
    ws, ls = w.get(conn, []), l.get(conn, [])
    sm = difflib.SequenceMatcher(a=[x[0] for x in ws], b=[x[0] for x in ls], autojunk=False)
    for tag, i, j, k, m in sm.get_opcodes():
        if tag == "equal":
            for (_, wu), (_, lu) in zip(ws[i:j], ls[k:m]):
                matched += 1
                starts.append((lu["t_start"] - wu["t_start"]) / 1e6)
                ends.append((lu["t_end"] - wu["t_end"]) / 1e6)
        else:
            missing.extend(x[0][0] for x in ws[i:j])
            extra.extend(x[0][0] for x in ls[k:m])
print(json.dumps({
    "wire": wc, "logs": lc, "matched_executions": matched,
    "missing": dict(collections.Counter(missing)), "extra": dict(collections.Counter(extra)),
    "start_log_minus_wire": dist(starts), "end_log_minus_wire": dist(ends),
}, ensure_ascii=False, indent=2))
if missing or extra:
    raise SystemExit(1)
