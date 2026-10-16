#!/usr/bin/env python3
"""sweep: turn a codebase scan into a table whose every cell must be filled.

Rows are units (functions, shared literals, code clones, registered mechanisms).
Columns are lenses (lenses.json). A cell is (unit, lens). Agents fill cells in
packets; the table, not the agent, decides what is still unchecked.
Needs graphify on PATH; its interpreter already ships the tree-sitter grammars, so without
tree_sitter here the script re-runs itself under graphify's Python.
"""
import argparse, fnmatch, hashlib, json, os, random, re, shutil, sqlite3, subprocess, sys, time
from collections import defaultdict

try:
    import tree_sitter  # noqa: F401
except ImportError:
    g = shutil.which("graphify")
    py = open(g).readline()[2:].strip() if g else ""
    if not py or os.path.realpath(py) == os.path.realpath(sys.executable):
        sys.exit("sweep needs tree-sitter: install graphify (uv tool install graphifyy) or pip install tree-sitter grammars")
    os.execv(py, [py, os.path.abspath(__file__), *sys.argv[1:]])

HERE = os.path.dirname(os.path.abspath(__file__))
LENSES = json.load(open(os.path.join(HERE, "lenses.json")))
LEASE_SECONDS = 2 * 3600
PACKET_LINES = 600  # ponytail: fixed budget per single-lens packet; tune if agents run out of context
PER_PACKET = {"lit": 10, "clone": 5, "same": 4, "sib": 4, "text": 1, "mech": 1, "hard": 8, "flow": 3}

# Untrusted input entering a function, and operations where such input does harm. Regexes over the function's
# source; JS and Python spellings. A flow unit pairs a source function with a sink function the call graph links.
FLOW_SOURCES = {
    "message": r"onMessage|onConnect|addEventListener\(\s*['\"]message|onmessage\s*=",
    "network": r"\bfetch\(|XMLHttpRequest|\.json\(\)|axios\.|requests\.(get|post)|urlopen",
    # Reading text off a page or the URL; finding an element (querySelector) or the code's own form fields is not input.
    "page": r"document\.cookie|\.innerText\b|\.textContent(?!\s*=)|location\.(href|search|hash)(?!\s*=)|URLSearchParams",
    "user": r"\bprompt\(|\binput\(|sys\.argv|process\.argv|req\.(body|query|params)|request\.(args|form|json)",
}
FLOW_SINKS = {
    "html": r"\.innerHTML\s*[+]?=|outerHTML\s*=|insertAdjacentHTML|document\.write\(",
    "code": r"\beval\(|new Function\(|executeScript|setTimeout\(\s*['\"`]",
    "navigation": r"tabs\.(create|update)\(|window\.open\(|location\.(href|assign|replace)\s*[=(]",
    "request": r"\bfetch\(|XMLHttpRequest|\.request\(",
    "permission": r"permissions\.request|declarativeNetRequest",
    "storage-write": r"storage\.(local|sync|session)\.set|localStorage\.setItem",
    "exec": r"child_process|\bexec\(|\bspawn\(|subprocess\.|os\.system|\.execute\(",
    "file": r"downloads\.download|writeFile|\bopen\([^)]*['\"]w",
}
FLOW_DEPTH, FLOW_PER_SOURCE = 3, 6

# ---------- storage ----------

SCHEMA = """
create table if not exists config(k text primary key, v text);
create table if not exists unit(id text primary key, kind text, name text, file text,
  line_start int, line_end int, hash text, meta text, alive int default 1);
create table if not exists cell(unit_id text, lens text, pass int default 1, status text,
  hash text, evidence text, packet text, leased_at real, at real,
  primary key(unit_id, lens, pass));
create table if not exists finding(id integer primary key, unit_id text, lens text, pass int,
  file text, line int, severity text, pattern text, summary text, scenario text,
  verdict text default 'open', verdict_note text, dup_of int, at real);
"""

def db(root):
    os.makedirs(os.path.join(root, ".sweep", "packets"), exist_ok=True)
    c = sqlite3.connect(os.path.join(root, ".sweep", "sweep.db"), timeout=60)
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA)
    return c

def cfg(c, k, default=None):
    r = c.execute("select v from config where k=?", (k,)).fetchone()
    return json.loads(r["v"]) if r else default

def h(s):
    return hashlib.sha1(s.encode()).hexdigest()[:16]

# ---------- inventory ----------

def lang_for(path):
    ext = path.rsplit(".", 1)[-1]
    try:
        import tree_sitter as ts
        if ext in ("js", "mjs", "cjs", "jsx"):
            import tree_sitter_javascript as m; return ts.Language(m.language())
        if ext == "ts":
            import tree_sitter_typescript as m; return ts.Language(m.language_typescript())
        if ext == "tsx":
            import tree_sitter_typescript as m; return ts.Language(m.language_tsx())
        mod = {"py": "python", "rs": "rust", "go": "go", "swift": "swift", "kt": "kotlin",
               "java": "java", "c": "c", "h": "c", "cpp": "cpp", "rb": "ruby", "php": "php"}.get(ext)
        if mod:
            m = __import__("tree_sitter_" + mod); return ts.Language(m.language())
    except Exception:
        pass
    return None

STRING_TYPES = {"string", "string_literal", "raw_string_literal", "interpreted_string_literal", "template_string"}

def parse(path, src):
    lang = lang_for(path)
    if not lang:
        return None
    import tree_sitter as ts
    return ts.Parser(lang).parse(src.encode())

def span_at(tree, line):
    """Largest node starting on `line` (0-based) - the whole declaration of a function."""
    if tree is None:
        return None
    n = tree.root_node.descendant_for_point_range((line, 0), (line, 10**6))
    best = None
    while n is not None and n.parent is not None:
        if n.start_point[0] == line and n.end_point[0] >= line:
            best = n
        elif n.start_point[0] < line:
            break
        n = n.parent
    # descendant_for_point_range on an indented line returns the line's container; walk down instead
    if best is None:
        for ch in walk(tree.root_node):
            if ch.start_point[0] == line and ch.end_point[0] > line:
                if best is None or ch.end_byte - ch.start_byte > best.end_byte - best.start_byte:
                    best = ch
            if ch.start_point[0] > line:
                break
    return best

def walk(n):
    stack = [n]
    while stack:
        x = stack.pop()
        yield x
        stack.extend(reversed(x.children))

def strings_in(tree):
    for n in walk(tree.root_node):
        if n.type in STRING_TYPES:
            if any(ch.type in ("template_substitution", "interpolation") for ch in n.children):
                continue
            t = n.text.decode(errors="replace")
            t = t[1:-1] if len(t) >= 2 and t[0] in "'\"`" else t
            yield n.start_point[0] + 1, t

TRAIL_PUNCT = re.compile(r"[\s：:。.，,；;！!？?、…]+$")

def literal_values(n):
    """Comparable values of a literal node worth tracking as possible hardcoded constants.
    Trailing punctuation is dropped ("保存设置失败：" + err matches "保存设置失败"), and every fixed
    piece of a template counts (`seen_${id}`, `<button>刷新</button>${x}`)."""
    if n.type in ("number", "integer", "float"):
        t = n.text.decode(errors="replace").replace("_", "")
        try:
            x = float(t)
        except ValueError:
            return []
        return [] if abs(x) < 3 else ["#" + (str(int(x)) if x == int(x) else t)]
    if n.type in STRING_TYPES:
        if any(ch.type in ("template_substitution", "interpolation") for ch in n.children):
            pieces = [ch.text.decode(errors="replace") for ch in n.children if ch.type == "string_fragment"]
        else:
            t = n.text.decode(errors="replace")
            pieces = [t[1:-1] if len(t) >= 2 and t[0] in "'\"`" else t]
        out = []
        for s in pieces:
            s = s.strip()
            if KEYLIKE.match(s):
                out.append(s)  # keys and prefixes keep their exact spelling
                continue
            # a CJK piece inside markup counts per text run or attribute value: `刷新</button>`, aria-label="下载…"
            for run in (re.findall(r"[^\"'=<>]*[一-鿿][^\"'=<>]*", s) if re.search(r"[<>]", s) else [s]):
                run = TRAIL_PUNCT.sub("", run.strip())
                if CJK.search(run) and interesting_string(run):
                    out.append(run)
        return out
    return []

KEYLIKE = re.compile(r"^(?=.*[_:./\-A-Z])[A-Za-z][\w:./\-]{2,80}$")
CJK = re.compile(r"[一-鿿]")

def interesting_string(s):
    s = s.strip()
    if CJK.search(s):
        return len(s) >= 2
    return bool(KEYLIKE.match(s)) and not s.startswith(("http", "./", "../")) and "/" not in s[:1]

def matches(path, globs):
    return any(fnmatch.fnmatch(path, g) for g in globs)

def scan(root, c):
    inc, exc = cfg(c, "include", ["**"]), cfg(c, "exclude", [])
    gpath = os.path.join(root, "graphify-out", "graph.json")
    subprocess.run(["graphify", "update" if os.path.exists(gpath) else "extract", root]
                   + ([] if os.path.exists(gpath) else ["--code-only"]),
                   check=True, stdout=subprocess.DEVNULL)
    g = json.load(open(gpath))
    in_corpus = lambda f: f and matches(f, inc) and not matches(f, exc)

    files, trees = {}, {}
    def load(f):
        if f not in files:
            try:
                files[f] = open(os.path.join(root, f), encoding="utf-8", errors="replace").read()
            except OSError:
                files[f] = ""
            trees[f] = parse(f, files[f])
        return files[f]

    # functions
    units, node_unit = {}, {}
    for n in g["nodes"]:
        f = n.get("source_file")
        if not (n.get("_callable") and n.get("label", "").endswith("()") and in_corpus(f)):
            continue
        start = int(n.get("source_location", "L1")[1:]) - 1
        src = load(f)
        sp = span_at(trees[f], start)
        end = sp.end_point[0] if sp is not None else start
        lines = src.splitlines()[start:end + 1]
        uid = "fn:" + n["id"]
        units[uid] = dict(id=uid, kind="fn", name=n["label"], file=f, line_start=start + 1,
                          line_end=end + 1, hash=h("\n".join(lines)), meta={"node": n["id"]})
        node_unit[n["id"]] = uid

    # call edges -> callers / callees (production callers only)
    nodes = {n["id"]: n for n in g["nodes"]}
    callers, callees = defaultdict(list), defaultdict(list)
    caller_ids, callee_ids = defaultdict(set), defaultdict(set)  # unit ids: impact of a change, and flow paths
    for e in g["links"]:
        if e.get("relation") not in ("calls", "indirect_call"):
            continue
        s, t = e["source"], e["target"]
        if s in node_unit and t in node_unit and node_unit[s] != node_unit[t]:
            caller_ids[node_unit[t]].add(node_unit[s])
            callee_ids[node_unit[s]].add(node_unit[t])
        if t in node_unit and in_corpus(e.get("source_file")):
            callers[node_unit[t]].append(f'{e.get("source_file")}:{e.get("source_location","")[1:]} ({nodes.get(s,{}).get("label","?")})')
        if s in node_unit and t in nodes:
            tn = nodes[t]
            callees[node_unit[s]].append(f'{tn.get("label")} @ {tn.get("source_file")}:{tn.get("source_location","")[1:]}')
    for uid, u in units.items():
        u["meta"].update(callers=sorted(set(callers[uid]))[:25], callees=sorted(set(callees[uid]))[:25],
                         n_callers=len(set(callers[uid])), caller_ids=sorted(caller_ids[uid]))

    by_file = defaultdict(list)
    for u in units.values():
        by_file[u["file"]].append(u)
    def innermost(f, line):
        best = None
        for u in by_file.get(f, ()):
            if u["line_start"] <= line <= u["line_end"] and (best is None or u["line_end"] - u["line_start"] < best["line_end"] - best["line_start"]):
                best = u
        return best

    # shared literals (the same key or sentence written in several files)
    for f in {n.get("source_file") for n in g["nodes"]}:
        if in_corpus(f):
            load(f)
    occ = defaultdict(list)
    for f, t in trees.items():
        if t is None or not in_corpus(f):
            continue
        for line, s in strings_in(t):
            if interesting_string(s):
                occ[s].append((f, line))
    for s, where in occ.items():
        if len({f for f, _ in where}) < 2:
            continue
        uid = "lit:" + h(s)
        units[uid] = dict(id=uid, kind="lit", name=s[:80], file=where[0][0], line_start=where[0][1],
                          line_end=where[0][1],
                          # content, not line numbers: an edit above must not reopen this cell
                          hash=h(json.dumps(sorted((f, "\n".join(files[f].splitlines()[max(0, l - 4):l + 3])) for f, l in where))),
                          meta={"text": s, "where": sorted(where)})

    # same-name functions in different files (copied helpers: setDisabledReason in popup and sidepanel)
    names = defaultdict(list)
    for u in [u for u in units.values() if u["kind"] == "fn"]:
        names[u["name"]].append(u)
    for name, us in names.items():
        if len({u["file"] for u in us}) < 2:
            continue
        uid = "same:" + h(name)
        units[uid] = dict(id=uid, kind="same", name=name, file=us[0]["file"], line_start=us[0]["line_start"],
                          line_end=us[0]["line_end"], hash=h("|".join(sorted(u["hash"] for u in us))),
                          meta={"where": sorted((u["file"], u["line_start"], u["line_end"]) for u in us)})

    # siblings: functions in different files that use the same callees and literals, so they likely
    # answer the same question. Very common callees carry no signal and are dropped.
    feats = defaultdict(set)
    for uid, cs in callees.items():
        feats[uid] |= {"call:" + x for x in cs}
    for f, t in trees.items():
        if t is None or not in_corpus(f):
            continue
        for line, s in strings_in(t):
            if interesting_string(s):
                u = innermost(f, line) if by_file else None
                if u:
                    feats[u["id"]].add("lit:" + s)
        for n in walk(t.root_node):  # platform/API calls the graph cannot resolve (chrome.tabs.create, Errors.text)
            if n.type in ("call_expression", "call"):
                fn_ = n.child_by_field_name("function")
                if fn_ is not None and fn_.type in ("member_expression", "attribute") and "\n" not in fn_.text.decode(errors="replace"):
                    u = innermost(f, n.start_point[0] + 1)
                    if u:
                        feats[u["id"]].add("api:" + re.sub(r"^(this|self)\.", "", fn_.text.decode(errors="replace"))[:80])
    df = defaultdict(int)
    for fs_ in feats.values():
        for x in fs_:
            df[x] += 1
    common = {x for x, n in df.items() if n > 25}
    feats = {k: v - common for k, v in feats.items() if len(v - common) >= 2}
    inv = defaultdict(set)
    for k, v in feats.items():
        for x in v:
            inv[x].add(k)
    best = defaultdict(list)
    for k, v in feats.items():
        cand = set().union(*(inv[x] for x in v)) - {k}
        for o in cand:
            if units[o]["file"] == units[k]["file"]:
                continue
            shared = v & feats[o]
            j = len(shared) / len(v | feats[o])
            if (len(shared) >= 2 and j >= 0.3) or (len(shared) >= 3 and j >= 0.15):
                best[k].append((j, o))
    pairs = set()
    for k, lst in best.items():
        for j, o in sorted(lst, reverse=True)[:3]:
            pairs.add(tuple(sorted((k, o))))
    for a_, b_ in pairs:
        ua, ub = units[a_], units[b_]
        uid = "sib:" + h(a_ + b_)
        units[uid] = dict(id=uid, kind="sib", name=f'{ua["name"]} ~ {ub["name"]}', file=ua["file"], line_start=ua["line_start"],
                          line_end=ua["line_end"], hash=h(ua["hash"] + ub["hash"]),
                          meta={"where": [(ua["file"], ua["line_start"], ua["line_end"]), (ub["file"], ub["line_start"], ub["line_end"])],
                                "shared": sorted(feats[a_] & feats[b_])[:20]})

    # text catalog: every user-visible sentence in the corpus, so "same situation, different words"
    # can be judged against all of them at once. One unit per file chunk; the catalog is one file.
    texts = defaultdict(list)
    for f, t in trees.items():
        if t is not None and in_corpus(f):
            texts[f] += [(l, s) for l, s in strings_in(t) if CJK.search(s)]
    for dirpath, _, fnames in os.walk(root):
        for fn_ in fnames:
            f = os.path.relpath(os.path.join(dirpath, fn_), root)
            if fn_.endswith(".html") and in_corpus(f) and ".sweep" not in f:
                for i, l in enumerate(open(os.path.join(root, f), encoding="utf-8", errors="replace").read().splitlines()):
                    for s in re.findall(r">([^<>]*[一-鿿][^<>]*)<|(?:title|placeholder|aria-label)=\"([^\"]*[一-鿿][^\"]*)\"", l):
                        texts[f].append((i + 1, (s[0] or s[1]).strip()))
    cat = ["# Text catalog: every user-visible string in the corpus, by file", ""]
    for f in sorted(texts):
        cat.append(f"## {f}")
        cat += [f"- {f}:{l}  {s}" for l, s in texts[f]]
    open(os.path.join(root, ".sweep", "text-catalog.md"), "w").write("\n".join(cat))
    CH = 50
    for f, ts_ in texts.items():
        for k in range(0, len(ts_), CH):
            chunk = ts_[k:k + CH]
            uid = f"text:{f}:{k // CH}"
            units[uid] = dict(id=uid, kind="text", name=f"{f} texts {k + 1}-{k + len(chunk)}", file=f,
                              line_start=chunk[0][0], line_end=chunk[-1][0], hash=h(json.dumps([s for _, s in chunk], ensure_ascii=False)),
                              meta={"texts": chunk})

    # hardcoded values: a literal equal to a named constant elsewhere, or the same number/key/sentence written
    # inline 2+ times with no constant. Covers numbers, same-file repeats and template prefixes, which lit does not.
    defs, uses = defaultdict(list), defaultdict(list)
    for f, t in trees.items():
        if t is None or not in_corpus(f):
            continue
        def_nodes = set()
        def collect(owner, node):
            if node is None:
                return
            if node.type in ("call_expression", "call"):  # Object.freeze({...})
                args = node.child_by_field_name("arguments")
                for ch in (args.named_children if args is not None else []):
                    collect(owner, ch)
                return
            if node.type in ("object", "dictionary"):
                for p in node.named_children:
                    if p.type == "pair":
                        k = p.child_by_field_name("key")
                        collect(f"{owner}.{k.text.decode(errors='replace').strip(chr(34) + chr(39))}", p.child_by_field_name("value"))
                return
            for v in literal_values(node):
                defs[v].append((owner, f, node.start_point[0] + 1))
                def_nodes.add(node.id)
        for n in walk(t.root_node):
            name = val = None
            if n.type == "variable_declarator":
                name, val = n.child_by_field_name("name"), n.child_by_field_name("value")
            elif n.type in ("assignment_expression", "assignment"):
                name, val = n.child_by_field_name("left"), n.child_by_field_name("right")
            if name is not None and re.fullmatch(r"[A-Z][A-Z0-9_]{2,}", name.text.decode(errors="replace").split(".")[-1]):
                collect(name.text.decode(errors="replace"), val)
        for n in walk(t.root_node):
            if n.id in def_nodes:
                continue
            for v in literal_values(n):
                uses[v].append((f, n.start_point[0] + 1))
    for v, where in uses.items():
        d = defs.get(v, [])
        if not (d or len(where) >= 2):
            continue
        where = sorted(set(where))
        uid = "hard:" + h(v)
        units[uid] = dict(id=uid, kind="hard", name=v[:80], file=where[0][0], line_start=where[0][1], line_end=where[0][1],
                          hash=h(json.dumps(sorted((f, files[f].splitlines()[l - 1].strip()) for f, l in where) + sorted(d), ensure_ascii=False)),
                          meta={"text": v, "where": where[:30], "n": len(where), "defs": d[:5]})

    # flows: a function that takes untrusted input, and a function that does something dangerous with data, linked
    # through the call graph (down its callees, or up to callers that receive its return value). One cell per pair
    # asks whether the input reaches the operation unchecked. Same-line source and sink (fetch as both) is skipped.
    def hits(u, table):
        out = {}
        for i, line in enumerate(files[u["file"]].splitlines()[u["line_start"] - 1:u["line_end"]], u["line_start"]):
            for k, rx in table.items():
                if k not in out and re.search(rx, line):
                    out[k] = i
        return out
    fns = {k: u for k, u in units.items() if u["kind"] == "fn"}
    srcs = {k: hits(u, FLOW_SOURCES) for k, u in fns.items()}
    sinks = {k: hits(u, FLOW_SINKS) for k, u in fns.items()}
    srcs = {k: v for k, v in srcs.items() if v}
    sinks = {k: v for k, v in sinks.items() if v}
    for a, sa in sorted(srcs.items()):
        found = []
        if a in sinks and not set(sinks[a].values()) <= set(sa.values()):
            found.append([a])
        for step in (callee_ids, caller_ids):  # input passed down as an argument, or returned up to a caller; never both
            seen_, frontier = {a}, [[a]]
            for _ in range(FLOW_DEPTH):
                frontier = [p + [n] for p in frontier for n in sorted(step[p[-1]]) if n in fns and n not in seen_ and not seen_.add(n)]
                found += [p for p in frontier if p[-1] in sinks]
        for path in sorted(found, key=lambda p: (len(p), p))[:FLOW_PER_SOURCE]:
            b = path[-1]
            uid = "flow:" + h(a + ">" + b)
            members = [fns[x] for x in path]
            units[uid] = dict(id=uid, kind="flow", name=f'{fns[a]["name"]} → {fns[b]["name"]}', file=fns[a]["file"],
                              line_start=fns[a]["line_start"], line_end=fns[a]["line_end"], hash=h("|".join(m["hash"] for m in members)),
                              meta={"source": {"kinds": sorted(sa), "at": f'{fns[a]["file"]}:{min(sa.values())}'},
                                    "sink": {"kinds": sorted(sinks[b]), "at": f'{fns[b]["file"]}:{min(sinks[b].values())}'},
                                    "path": [f'{m["name"]} @ {m["file"]}:{m["line_start"]}' for m in members],
                                    "where": [(m["file"], m["line_start"], m["line_end"]) for m in members]})

    # clones: the same code written in several functions
    W = 5
    win = defaultdict(list)
    for f, src in files.items():
        if not in_corpus(f):
            continue
        sig = [(i + 1, re.sub(r"\s+", " ", l.strip())) for i, l in enumerate(src.splitlines())]
        sig = [(i, l) for i, l in sig if len(l) > 3 and not l.startswith(("//", "#", "*", "/*")) and l not in ("});", "})", "};", "}", "{")]
        for k in range(len(sig) - W + 1):
            chunk = sig[k:k + W]
            win[h("\n".join(l for _, l in chunk))].append((f, chunk[0][0], chunk[-1][0]))
    groups = defaultdict(list)
    for hits in win.values():
        if len(hits) < 2:
            continue
        owners = []
        for f, a, b in hits:
            u = innermost(f, a)
            owners.append((u["id"] if u else f"{f}:top", f, a, b))
        key = tuple(sorted({o[0] for o in owners}))
        if len(key) >= 2:
            groups[key].extend(owners)
    for key, owners in groups.items():
        span = defaultdict(lambda: [10**9, 0, ""])
        for oid, f, a, b in owners:
            s = span[oid]; s[0] = min(s[0], a); s[1] = max(s[1], b); s[2] = f
        where = sorted((v[2], v[0], v[1]) for v in span.values())
        body = "".join(files[f].splitlines()[a - 1] for f, a, _ in where[:1])
        uid = "clone:" + h("|".join(key))
        units[uid] = dict(id=uid, kind="clone", name=" ~ ".join(k.split(":")[-1] for k in key)[:120],
                          file=where[0][0], line_start=where[0][1], line_end=where[0][2],
                          hash=h(json.dumps([(f, files[f].splitlines()[a - 1:b]) for f, a, b in where])),
                          meta={"where": where})

    # mechanisms are registered by agents; keep them, rehash from their members' files
    for r in c.execute("select * from unit where kind='mech' and alive=1"):
        units[r["id"]] = dict(r) | {"meta": json.loads(r["meta"])}

    return units

def sync(c, units):
    now = time.time()
    seen = set()
    reopened = added = 0
    changed = []
    for u in units.values():
        seen.add(u["id"])
        old = c.execute("select hash from unit where id=?", (u["id"],)).fetchone()
        if old and old["hash"] != u["hash"] and u["kind"] == "fn":
            changed.append(u["id"])
        c.execute("insert or replace into unit values(?,?,?,?,?,?,?,?,1)",
                  (u["id"], u["kind"], u["name"], u["file"], u["line_start"], u["line_end"], u["hash"], json.dumps(u["meta"], ensure_ascii=False)))
        src = None
        for lens in LENSES:
            if lens["kind"] != u["kind"]:
                continue
            ok = applies(lens, u, root_files_cache)
            row = c.execute("select status, hash from cell where unit_id=? and lens=? and pass=1", (u["id"], lens["id"])).fetchone()
            status = "open" if ok else "na"
            if row is None:
                c.execute("insert into cell(unit_id,lens,pass,status,hash,at) values(?,?,1,?,?,?)", (u["id"], lens["id"], status, u["hash"], now))
                added += ok
            elif row["hash"] != u["hash"]:
                c.execute("update cell set status=?, hash=?, evidence=null, packet=null, at=? where unit_id=? and lens=? and pass=1",
                          (status, u["hash"], now, u["id"], lens["id"]))
                reopened += ok and row["status"] != "open"
    # A changed function can break what its callers assumed (return shape, errors, timing): their filled cells
    # reopen too, one level up. Their own hash is unchanged, so record() still accepts the answers.
    via = 0
    for uid in changed:
        for caller in units[uid]["meta"].get("caller_ids", []):
            via += c.execute("update cell set status='open', evidence=null, packet=null, at=? where unit_id=? and pass=1 and status in ('clean','finding')",
                             (now, caller)).rowcount
    reopened += via
    gone = [r["id"] for r in c.execute("select id from unit where alive=1") if r["id"] not in seen]
    for uid in gone:
        c.execute("update unit set alive=0 where id=?", (uid,))
        c.execute("update cell set status='gone' where unit_id=?", (uid,))
    c.commit()
    return added, reopened, len(gone)

root_files_cache = {}
def unit_source(root, u, pad=0):
    f = u["file"]
    if f not in root_files_cache:
        try:
            root_files_cache[f] = open(os.path.join(root, f), encoding="utf-8", errors="replace").read().splitlines()
        except OSError:
            root_files_cache[f] = []
    lines = root_files_cache[f]
    a, b = max(1, u["line_start"] - pad), min(len(lines), u["line_end"] + pad)
    return "\n".join(f"L{i}: {lines[i-1]}" for i in range(a, b + 1))

def applies(lens, u, _):
    rule = lens.get("applies", "always")
    if rule == "always":
        return True
    if rule == "no_callers":
        return u["meta"].get("n_callers", 0) == 0
    src = "\n".join(root_files_cache.get(u["file"], [])[u["line_start"] - 1:u["line_end"]])
    return re.search(rule, src) is not None

# ---------- commands ----------

def cmd_init(a):
    c = db(a.root)
    c.execute("insert or replace into config values('include',?)", (json.dumps(a.include or ["**"]),))
    c.execute("insert or replace into config values('exclude',?)", (json.dumps(a.exclude or []),))
    c.commit()
    ex = os.path.join(a.root, ".git", "info", "exclude")
    if os.path.isdir(os.path.dirname(ex)):
        cur = open(ex).read() if os.path.exists(ex) else ""
        with open(ex, "a") as fh:
            for p in (".sweep/", "graphify-out/"):
                if p not in cur.split():
                    fh.write(f"\n{p}\n")
    cmd_scan(a)

def cmd_scan(a):
    c = db(a.root)
    root_files_cache.clear()
    units = scan(a.root, c)
    for u in units.values():
        unit_source(a.root, u)  # warm cache for applies()
    added, reopened, gone = sync(c, units)
    print(f"units {len(units)}  new cells {added}  reopened {reopened}  gone units {gone}")
    cmd_status(a)

def cmd_status(a):
    c = db(a.root)
    rows = c.execute("""select u.kind, c.lens, c.status, count(*) n from cell c join unit u on u.id=c.unit_id
                        where c.pass=1 and u.alive=1 and (?='' or u.file like ? or u.meta like ?)
                        group by 1,2,3""", (a.path or "", f"%{a.path}%", f"%{a.path}%")).fetchall()
    t = defaultdict(lambda: defaultdict(int))
    for r in rows:
        t[r["lens"]][r["status"]] += r["n"]
    tot = defaultdict(int)
    print(f'{"lens":<10}{"open":>7}{"leased":>8}{"clean":>7}{"finding":>9}{"na":>6}  done')
    for lens in [l["id"] for l in LENSES]:
        s = t.get(lens, {})
        need = s.get("open", 0) + s.get("leased", 0) + s.get("clean", 0) + s.get("finding", 0)
        done = s.get("clean", 0) + s.get("finding", 0)
        for k, v in s.items():
            tot[k] += v
        print(f'{lens:<10}{s.get("open",0):>7}{s.get("leased",0):>8}{s.get("clean",0):>7}{s.get("finding",0):>9}{s.get("na",0):>6}  {done}/{need}')
    need = tot["open"] + tot["leased"] + tot["clean"] + tot["finding"]
    print(f'coverage {tot["clean"] + tot["finding"]}/{need} cells' + (f' under "{a.path}"' if a.path else ""))
    nf = c.execute("select count(*) from finding where dup_of is null and pass=1").fetchone()[0]
    print(f"findings {nf}")

def cmd_next(a):
    """Lease up to one packet of open cells; write it as a markdown file and print its path."""
    c = db(a.root)
    now = time.time()
    # workers call next in parallel: take the write lock before reading open cells, or two workers lease the same ones
    c.execute("BEGIN IMMEDIATE")
    c.execute("update cell set status='open', packet=null where status='leased' and leased_at<?", (now - LEASE_SECONDS,))
    q = """select c.unit_id, c.lens, u.* from cell c join unit u on u.id=c.unit_id
           where c.status='open' and c.pass=? and u.alive=1 and (?='' or u.file like ? or u.meta like ?)
           order by case u.kind when 'fn' then 1 else 0 end, u.file, u.line_start"""
    rows = c.execute(q, (a.pass_, a.path or "", f"%{a.path}%", f"%{a.path}%")).fetchall()
    if not rows:
        print("NONE"); return
    # one lens per packet: an agent holding one checklist goes deeper than one juggling nine
    kind, lens0 = rows[0]["kind"], rows[0]["lens"]
    by_unit = defaultdict(list)
    order = []
    for r in rows:
        if r["kind"] != kind or r["lens"] != lens0 or (kind == "fn" and r["file"] != rows[0]["file"]):
            continue
        if r["unit_id"] not in by_unit:
            order.append(r)
        by_unit[r["unit_id"]].append(r["lens"])
    budget, picked = (PACKET_LINES, []) if kind == "fn" else (PER_PACKET[kind], [])
    for r in order:
        size = r["line_end"] - r["line_start"] + 1 if kind == "fn" else 1
        if picked and size > budget:
            break
        picked.append(r); budget -= size
    pid = f"P{int(now*1000)%10**9:09d}{os.urandom(2).hex()}" + (f"-p{a.pass_}" if a.pass_ > 1 else "")
    lensmap = {l["id"]: l for l in LENSES}
    out = [f"# Packet {pid}", "", f"Project root: `{a.root}`", "",
           "Fill EVERY cell below. Read the project's own rules first (README, AGENTS.md / CLAUDE.md, design docs) if you have not.",
           "You may open any file to check callers, siblings and docs. Do not edit project files.", ""]
    skeleton = []
    used = set()
    for r in picked:
        u = dict(r); u["meta"] = json.loads(u["meta"])
        out.append(f"## {u['id']}  —  {u['name']}  ({u['file']}:{u['line_start']}-{u['line_end']})")
        if kind == "fn":
            out += ["```", unit_source(a.root, u), "```"]
            out.append("Callers: " + ("; ".join(u["meta"]["callers"]) or "none found by graph (check event listeners, exports, dynamic calls)"))
            out.append("Callees: " + ("; ".join(u["meta"]["callees"]) or "none"))
        elif kind == "lit":
            out.append(f"Text: `{u['meta']['text']}`")
            pad = 3 if CJK.search(u["meta"]["text"]) else 6  # keys and message names need the fields around them
            for f, line in u["meta"]["where"]:
                out += [f"- {f}:{line}", "```", unit_source(a.root, dict(file=f, line_start=line, line_end=line), pad=pad), "```"]
        elif kind == "clone":
            for f, s, e in u["meta"]["where"]:
                out += [f"- {f}:{s}-{e}", "```", unit_source(a.root, dict(file=f, line_start=s, line_end=e), pad=2), "```"]
        elif kind == "flow":
            m = u["meta"]
            out.append(f'Source ({", ".join(m["source"]["kinds"])}) at {m["source"]["at"]}; sink ({", ".join(m["sink"]["kinds"])}) at {m["sink"]["at"]}')
            out.append("Call path: " + " → ".join(m["path"]))
            for f, s_, e in m["where"]:
                out += [f"- {f}:{s_}-{e}", "```", unit_source(a.root, dict(file=f, line_start=s_, line_end=min(e, s_ + 150))), "```"]
        elif kind in ("same", "sib"):
            if kind == "sib":
                out.append("Shared callees/literals: " + "; ".join(u["meta"]["shared"]))
            for f, s, e in u["meta"]["where"]:
                out += [f"- {f}:{s}-{e}", "```", unit_source(a.root, dict(file=f, line_start=s, line_end=e)), "```"]
        elif kind == "hard":
            m = u["meta"]
            out.append(f"Value: `{m['text']}`  written inline at {m['n']} site(s)" + (f", first {len(m['where'])} shown" if m["n"] > len(m["where"]) else ""))
            out.append("Defined as: " + ("; ".join(f"{n} @ {f}:{l}" for n, f, l in m["defs"]) or "no named constant or table entry"))
            for f, line in m["where"]:
                out += [f"- {f}:{line}", "```", unit_source(a.root, dict(file=f, line_start=line, line_end=line), pad=2), "```"]
        elif kind == "text":
            out.append(f"Full catalog of every user-visible string in the project: `{os.path.join(a.root, '.sweep', 'text-catalog.md')}` (read it all).")
            out += [f"- {u['file']}:{l}  {s}" for l, s in u["meta"]["texts"]]
        elif kind == "mech":
            out.append(json.dumps(u["meta"], ensure_ascii=False, indent=1))
        out.append("Cells: " + ", ".join(by_unit[u["id"]]))
        out.append("")
        for lid in by_unit[u["id"]]:
            used.add(lid)
            skeleton.append({"unit": u["id"], "lens": lid, "status": "clean|finding",
                             "evidence": "which lines you read and why they are fine, e.g. 'L120-L131 ...'",
                             "findings": []})
        c.execute(f"update cell set status='leased', packet=?, leased_at=? where unit_id=? and pass=? and lens in ({','.join('?'*len(by_unit[u['id']]))})",
                  (pid, now, u["id"], a.pass_, *by_unit[u["id"]]))
    out += ["# Lenses", ""]
    for lid in sorted(used):
        l = lensmap[lid]
        out += [f"## {lid} — {l['title']}", l["ask"], ""]
    out += ["# Answer format", "",
            "Write a JSON array with one object per cell, then run:",
            f"`{sys.executable} {os.path.abspath(__file__)} --root {a.root} record {pid} <answers.json>`",
            "A finding object: {\"file\", \"line\", \"severity\": \"high|medium|low\", \"pattern\": short kebab slug naming the defect class, "
            "\"summary\": one sentence, \"scenario\": concrete input/state -> wrong result}.",
            "If you meet a mechanism (registry, dispatcher, list of handlers, set of entry points that must behave alike) "
            "whose members you did not all check, register it:",
            f"`{sys.executable} {os.path.abspath(__file__)} --root {a.root} mech \"<name>\" \"<what every member must do>\" <file:line of the mechanism>`",
            "", "```json", json.dumps(skeleton, indent=1, ensure_ascii=False), "```"]
    path = os.path.join(a.root, ".sweep", "packets", pid + ".md")
    open(path, "w").write("\n".join(out))
    c.commit()
    print(path)

LINE_REF = re.compile(r"L\d+|:\d+")

def cmd_record(a):
    c = db(a.root)
    ans = json.load(open(a.answers))
    leased = {(r["unit_id"], r["lens"], r["pass"]): r for r in c.execute("select * from cell where packet=? and status='leased'", (a.packet,))}
    if not leased:
        sys.exit(f"packet {a.packet} has no leased cells (expired or already recorded)")
    errors, got, stale = [], {}, 0
    for x in ans:
        key = next((k for k in leased if k[0] == x.get("unit") and k[1] == x.get("lens")), None)
        if key is None:
            stale += 1; continue  # reopened by a scan while leased, or a typo; typos still fail the "not answered" check
        st, ev, fs = x.get("status"), (x.get("evidence") or "").strip(), x.get("findings") or []
        if st not in ("clean", "finding"):
            errors.append(f"{key[:2]}: status must be clean or finding")
        elif st == "clean" and (len(ev) < 25 or not LINE_REF.search(ev)):
            errors.append(f"{key[:2]}: clean needs evidence naming the lines read (L123 or file:123)")
        elif st == "finding" and not fs:
            errors.append(f"{key[:2]}: status finding but no findings")
        for f in fs:
            miss = [k for k in ("file", "line", "summary", "scenario", "pattern") if not f.get(k)]
            if miss:
                errors.append(f"{key[:2]}: finding missing {miss}")
        got[key] = (st, ev, fs)
    missing = [k[:2] for k in leased if k not in got]
    if missing:
        errors.append(f"cells not answered: {missing}")
    if errors:
        sys.exit("REJECTED, nothing recorded:\n- " + "\n- ".join(errors))
    now = time.time()
    for (uid, lens, p), (st, ev, fs) in got.items():
        cur = c.execute("select hash from unit where id=?", (uid,)).fetchone()["hash"]
        if cur != leased[(uid, lens, p)]["hash"]:
            c.execute("update cell set status='open', packet=null where unit_id=? and lens=? and pass=?", (uid, lens, p))
            continue  # code changed under the packet; cell goes back to open
        c.execute("update cell set status=?, evidence=?, at=? where unit_id=? and lens=? and pass=?", (st, ev, now, uid, lens, p))
        for f in fs:
            c.execute("insert into finding(unit_id,lens,pass,file,line,severity,pattern,summary,scenario,at) values(?,?,?,?,?,?,?,?,?,?)",
                      (uid, lens, p, f["file"], int(re.sub(r"\D.*", "", str(f["line"])) or 0), f.get("severity", "medium"),
                       f["pattern"], f["summary"], f["scenario"], now))
    c.commit()
    print(f"recorded {len(got)} cells, {sum(len(v[2]) for v in got.values())} findings" + (f", ignored {stale} answers for cells no longer leased" if stale else ""))

def cmd_release(a):
    """Return leased cells to open. Only when no worker is running (or for one named packet)."""
    c = db(a.root)
    n = c.execute("update cell set status='open', packet=null where status='leased' and (?='' or packet=?)", (a.packet, a.packet)).rowcount
    c.commit()
    print(f"released {n} cells")

def cmd_mech(a):
    c = db(a.root)
    f, _, line = a.where.rpartition(":")
    uid = "mech:" + h(a.name)
    if c.execute("select 1 from unit where id=?", (uid,)).fetchone():
        print(f"exists {uid}"); return
    meta = {"rule": a.rule, "where": a.where}
    c.execute("insert into unit values(?,?,?,?,?,?,?,?,1)", (uid, "mech", a.name, f, int(line or 1), int(line or 1), h(a.name + a.rule), json.dumps(meta, ensure_ascii=False)))
    for lens in LENSES:
        if lens["kind"] == "mech":
            c.execute("insert or ignore into cell(unit_id,lens,pass,status,hash,at) values(?,?,1,'open',?,?)", (uid, lens["id"], h(a.name + a.rule), time.time()))
    c.commit()
    print(f"registered {uid}")

def overlap(a, b, slack=3):
    return a["file"] == b["file"] and abs((a["line"] or 0) - (b["line"] or 0)) <= slack

def cmd_dedupe(a):
    c = db(a.root)
    fs = [dict(r) for r in c.execute("select * from finding where pass=1 order by id")]
    keep = []
    for f in fs:
        dup = next((k for k in keep if overlap(k, f) and (k["pattern"] == f["pattern"] or k["unit_id"] == f["unit_id"])), None)
        c.execute("update finding set dup_of=? where id=?", (dup["id"] if dup else None, f["id"]))
        if not dup:
            keep.append(f)
    c.commit()
    print(f"{len(fs)} findings -> {len(keep)} after merging same place + same pattern (semantic merges are the verifier's job)")

def cmd_report(a):
    c = db(a.root)
    rows = [dict(r) for r in c.execute("select * from finding where pass=1 and dup_of is null and verdict!='rejected' order by severity, file, line")]
    dups = defaultdict(list)
    for r in c.execute("select id, dup_of from finding where dup_of is not null"):
        dups[r["dup_of"]].append(r["id"])
    print("| id | sev | where | lens | pattern | summary | scenario | verdict |\n|---|---|---|---|---|---|---|---|")
    for r in rows:
        extra = f" (+{len(dups[r['id']])} dup)" if dups[r["id"]] else ""
        print(f"| F{r['id']} | {r['severity']} | {r['file']}:{r['line']} | {r['lens']} | {r['pattern']} | {r['summary']}{extra} | {r['scenario']} | {r['verdict']} |".replace("\n", " "))
    pats = defaultdict(set)
    for r in rows:
        pats[r["pattern"]].add(r["unit_id"])
    lint = sorted(((p, len(u)) for p, u in pats.items() if len(u) >= 2), key=lambda x: -x[1])
    if lint:
        print("\nPatterns seen in 2+ units (candidates for a lint rule):")
        for p, n in lint:
            print(f"- {p}: {n} units")

def cmd_judge(a):
    c = db(a.root)
    c.execute("update finding set verdict=?, verdict_note=? where id=?", (a.verdict, a.note, int(a.id.lstrip("F"))))
    c.commit()

def cmd_sample(a):
    """Second independent pass on a random share of done cells, for the miss-rate estimate."""
    c = db(a.root)
    done = [dict(r) for r in c.execute("select unit_id, lens, hash from cell where pass=1 and status in ('clean','finding')")]
    random.seed(a.seed)
    pick = random.sample(done, max(1, int(len(done) * a.pct / 100))) if done else []
    for r in pick:
        c.execute("insert or ignore into cell(unit_id,lens,pass,status,hash,at) values(?,?,2,'open',?,?)", (r["unit_id"], r["lens"], r["hash"], time.time()))
    c.commit()
    print(f"queued {len(pick)} cells for pass 2; fetch them with: next --pass 2")

def cmd_estimate(a):
    c = db(a.root)
    cells = {(r["unit_id"], r["lens"]) for r in c.execute("select unit_id, lens from cell where pass=2 and status in ('clean','finding')")}
    f1 = [dict(r) for r in c.execute("select * from finding where pass=1 and verdict!='rejected'") if (r["unit_id"], r["lens"]) in cells]
    f2 = [dict(r) for r in c.execute("select * from finding where pass=2 and verdict!='rejected'")]
    m = sum(1 for x in f2 if any(x["unit_id"] == y["unit_id"] and overlap(x, y, 6) for y in f1))
    print(f"sampled cells {len(cells)}  pass1 findings {len(f1)}  pass2 findings {len(f2)}  both {m}")
    if m:
        n = len(f1) * len(f2) / m
        print(f"estimated defects in sample ≈ {n:.1f}; pass 1 found {len(f1)} → recall ≈ {len(f1)/n:.0%}")
    else:
        print("no overlap yet: too few findings to estimate (sample more, or recall is low)")

def main():
    p = argparse.ArgumentParser(prog="sweep")
    p.add_argument("--root", default=os.getcwd())
    sp = p.add_subparsers(dest="cmd", required=True)
    x = sp.add_parser("init"); x.add_argument("--include", action="append"); x.add_argument("--exclude", action="append"); x.add_argument("--path", default="")
    sp.add_parser("scan").add_argument("--path", default="")
    sp.add_parser("status").add_argument("--path", default="")
    x = sp.add_parser("next"); x.add_argument("--path", default=""); x.add_argument("--pass", dest="pass_", type=int, default=1)
    x = sp.add_parser("record"); x.add_argument("packet"); x.add_argument("answers")
    sp.add_parser("release").add_argument("packet", nargs="?", default="")
    x = sp.add_parser("mech"); x.add_argument("name"); x.add_argument("rule"); x.add_argument("where")
    sp.add_parser("dedupe"); sp.add_parser("report")
    x = sp.add_parser("judge"); x.add_argument("id"); x.add_argument("verdict", choices=["confirmed", "rejected", "fixed", "open"]); x.add_argument("note", nargs="?", default="")
    x = sp.add_parser("sample"); x.add_argument("--pct", type=float, default=10); x.add_argument("--seed", type=int, default=1)
    sp.add_parser("estimate")
    a = p.parse_args()
    a.root = os.path.abspath(a.root)
    globals()["cmd_" + a.cmd](a)

if __name__ == "__main__":
    main()
