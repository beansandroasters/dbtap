"""Match wire and log recordings by session-local SQL, values, and execution order.

Count Execute messages within wire Units, distinguishing empty Sync units and pipelines.
Treat a multi-statement Query as one group; intended for e2e measurements, not large recordings.
"""
import argparse
import collections
import difflib
import json
import statistics

p = argparse.ArgumentParser()
p.add_argument("wire")
p.add_argument("logs")
p.add_argument("--application-prefix", required=True)
a = p.parse_args()


def cstr(b):
    pos = b.index(0)
    return b[:pos].decode(), b[pos + 1:]


def commands(u, statements, portals):
    b = bytes(u["req"])
    pos, result = 0, []
    while pos < len(b):
        tag, n = chr(b[pos]), int.from_bytes(b[pos + 1:pos + 5], "big")
        data = b[pos + 5:pos + 1 + n]
        pos += n + 1
        if tag == "Q":
            result.append((cstr(data)[0], ()))
        elif tag == "P":
            name, data = cstr(data)
            sql, data = cstr(data)
            types = [int.from_bytes(data[i:i + 4], "big") for i in range(2, len(data), 4)]
            statements[name] = (sql, types)
        elif tag == "B":
            portal, data = cstr(data)
            stmt, data = cstr(data)
            sql, types = statements[stmt]
            nf = int.from_bytes(data[:2], "big")
            formats = [int.from_bytes(data[2 + 2*i:4 + 2*i], "big") for i in range(nf)]
            data = data[2 + 2*nf:]
            nv, data = int.from_bytes(data[:2], "big"), data[2:]
            values = []
            for i in range(nv):
                n, data = int.from_bytes(data[:4], "big", signed=True), data[4:]
                if n == -1:
                    values.append(None)
                    continue
                v, data = data[:n], data[n:]
                fmt = formats[0] if len(formats) == 1 else (formats[i] if formats else 0)
                oid = types[i] if i < len(types) else 0
                if fmt == 1 and oid in (20, 21, 23):
                    values.append(str(int.from_bytes(v, "big", signed=True)))
                elif fmt == 0:
                    values.append(v.decode())
                else:
                    raise ValueError(f"Binary type unsupported by this test: {oid}")
            portals[portal] = (sql, tuple(values))
        elif tag == "E":
            portal, _ = cstr(data)
            result.append(portals[portal])
    if u["origin"] and u["skip"]:
        return [(u["sql"], ())]
    return result


def read(path):
    info, sessions = {}, collections.defaultdict(list)
    statements, portals = collections.defaultdict(dict), collections.defaultdict(dict)
    counts = collections.Counter()
    for line in open(path):
        event = json.loads(line)
        if event["type"] == "open":
            i = event["info"]
            app = dict(i["params"]).get("application_name", "")
            if app.startswith(a.application_prefix):
                info[i["conn"]] = app
                sessions[app]  # Retain sessions even if all their units are missing.
        elif event["type"] == "unit":
            u = event["unit"]
            conn = u["conn"]
            if conn not in info:
                continue
            counts["units"] += 1
            if u["skip"]:
                counts["skipped"] += 1
            ops = commands(u, statements[conn], portals[conn])
            if not ops:
                counts["units_without_execution"] += 1
            if len(ops) > 1:
                counts["units_with_multiple_executions"] += 1
            for key in ops:
                sessions[info[conn]].append((key, u, len(ops)))
                counts["executions"] += 1
    return sessions, dict(counts)


wire, wc = read(a.wire)
logs, lc = read(a.logs)
missing, extra, starts, ends = [], [], [], []
matched = replayable = 0
for name in sorted(wire.keys() | logs.keys()):
    w, l = wire.get(name, []), logs.get(name, [])
    sm = difflib.SequenceMatcher(a=[x[0] for x in w], b=[x[0] for x in l], autojunk=False)
    for tag, i, j, k, m in sm.get_opcodes():
        if tag == "equal":
            for (_, wu, wn), (_, lu, _) in zip(w[i:j], l[k:m]):
                matched += 1
                replayable += lu["skip"] is None
                if wn == 1 and lu["observed"]["duration"]:
                    starts.append((lu["t_start"] - wu["t_start"]) / 1e6)
                    ends.append((lu["t_end"] - wu["t_end"]) / 1e6)
        else:
            missing.extend(x[0][0] for x in w[i:j])
            extra.extend(x[0][0] for x in l[k:m])


def distribution(values):
    if not values:
        return {"n": 0}
    v = sorted(values)
    return {"n": len(v), "min_ms": v[0], "p50_ms": v[round((len(v)-1)*.5)],
            "p95_ms": v[round((len(v)-1)*.95)], "max_ms": v[-1],
            "mean_ms": statistics.mean(v)}


print(json.dumps({
    "wire": wc, "logs": lc, "matched_executions": matched,
    "matched_replayable": replayable,
    "missing": dict(collections.Counter(missing)), "extra": dict(collections.Counter(extra)),
    "start_log_minus_wire": distribution(starts), "end_log_minus_wire": distribution(ends),
}, ensure_ascii=False, indent=2))
if missing or extra:
    raise SystemExit(1)
