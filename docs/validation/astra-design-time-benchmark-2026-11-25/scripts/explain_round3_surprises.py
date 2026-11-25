import sys, runpy, io, contextlib
sys.argv = ["x"]
src = open("/w/docs/validation/astra-design-time-benchmark-2026-11-25/scripts/seeded_flaws3.py", encoding="utf-8").read().split("# ---------------- Part 2")[0]
g = {}
exec(compile(src, "r3", "exec"), g)
AE = g["AE"]
def show(label, builder, change):
    c = list(builder()); c[0] = g["copy"].deepcopy(c[0]); change(c)
    cx = g["mkctx"](others=c[1], **c[3])
    b = AE.build(AE.Source(c[0], g["rows_of"](c[0]), dict(c[2])), cx)
    out = AE.describe(b, cx, 0)
    print("==", label, out["verdict"], "| hitl_tools:", sorted(b.estate.agents[g["NAME"]].hitl_tools), "| dept:", b.estate.agents[g["NAME"]].dept)
    print("   rows:", {r["id"]: r["status"] for r in g["rows_of"](c[0]) if r["id"] in ("ASI01", "ASI02", "ASI10")})
    for p in out["paths"][:2]:
        print("   path", p["resource_name"], "tier", p["tier"], p["verdict"], {(x["kind"], x["agent"][:6]): x["status"] for x in p["controls"] if x["status"] != "SAT"})
    print("   notes:", [n[:90] for n in out["notes"]])
show("R4 write tool declared read-only", g["b1"], g["f_r4"])
show("R5 approval gates the agent", g["b1"], g["f_r5"])
show("R8 agent unknown to the organisation", g["b1"], g["f_r8"])
show("P1 R1 with tolerance 4", g["b1"], g["f_r1b"])
