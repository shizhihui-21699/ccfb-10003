#!/usr/bin/env python3
"""Crash triage for the libtlv fuzzers.

Pipeline, per run:

  1. Replay every artifact under the instrumented binary (cheap, one process
     each) and classify it: sanitizer kind, first meaningful stack frames,
     report detail;
  2. Group artifacts by stack fingerprint, so one root cause found fifty ways
     is reported once;
  3. Minimize exactly ONE representative per group with libFuzzer's
     -minimize_crash (the expensive step, so it is not done per artifact);
  4. Verify the minimized sample still reproduces, and if so file it under
     corpus/regression/<class>/;
  5. Write artifacts/triage/<class>.md per class plus summary.json and an
     INDEX.md, and optionally a dedup index of all raw artifacts.

A crash that no longer reproduces against the current build is reported as
STALE and kept for the record, never silently dropped.

Usage:
  python3 tools/triage.py --crashes build/legacy-crashes \
      --binary build/fuzz_legacy \
      --regression build/legacy-regression \
      --artifacts build/legacy-artifacts
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

# Two shapes occur:
#   symbolized:   "#0 0xADDR in FUNC /path/file.c:LINE:COL"
#   unsymbolized: "#0 0xADDR in FUNC +0xOFFSET (/path/binary:arm64+0x...)"
FRAME_RE = re.compile(
    r"^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+?)"
    r"(?:\s+/\S*?([^/\s]+):(\d+)(?::\d+)?"
    r"|\s+\+0x[0-9a-fA-F]+\s*\(|\s*$|\s*\()"
)
ERROR_RE = re.compile(r"ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer|libFuzzer):\s*(.*)")
SUMMARY_RE = re.compile(r"SUMMARY: (\S+):\s*(.*)")

# Frames that are runtime noise and would collapse distinct bugs into one class.
NOISE_RE = re.compile(
    r"(__sanitizer|__asan|__ubsan|fuzzer::|_sigtramp|pthread_kill|abort\+|"
    r"^\w*start\+|start\+0x|dyld|libsystem|libclang_rt|libdyld|^main\+)"
)

FRAMES_PER_CLASS = 3   # how many frames make up the fingerprint
FRAMES_DISPLAY = 8     # how many frames to show in the report


@dataclass
class Crash:
    path: str
    sha: str
    size: int
    reproduces: bool = False
    exit_code: int = 0
    kind: str = "unknown"
    frames: list = field(default_factory=list)
    detail: str = ""
    fingerprint: str = ""
    minimized_path: str | None = None
    minimized_size: int = 0
    minimized_reproduces: bool = False


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _find_symbolizer() -> str | None:
    """ASan/libFuzzer only emit file:line when a symbolizer is reachable.

    Apple's dyld paths are not resolved by the bundled `atos`, so we point the
    runtime at LLVM's own symbolizer when it is installed.
    """
    candidates = [
        os.environ.get("ASAN_SYMBOLIZER_PATH"),
        "/opt/homebrew/opt/llvm/bin/llvm-symbolizer",
        "/usr/local/opt/llvm/bin/llvm-symbolizer",
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c
    for d in os.environ.get("PATH", "").split(os.pathsep):
        c = os.path.join(d, "llvm-symbolizer")
        if os.path.exists(c):
            return c
    return None


SYMBOLIZER = _find_symbolizer()
RUNTIME_ENV = dict(os.environ)
if SYMBOLIZER:
    RUNTIME_ENV["ASAN_SYMBOLIZER_PATH"] = SYMBOLIZER
    RUNTIME_ENV["UBSAN_SYMBOLIZER_PATH"] = SYMBOLIZER
    RUNTIME_ENV["PATH"] = os.path.dirname(SYMBOLIZER) + os.pathsep + \
        RUNTIME_ENV.get("PATH", "")


def run_binary(binary: str, sample: str, extra: list[str] | None = None,
               timeout: int = 60) -> tuple[int, str]:
    cmd = [binary, *(extra or []), sample]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=RUNTIME_ENV)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        err = exc.stderr or ""
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        return 124, out + err
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def parse_frames(report: str) -> list[str]:
    """Return frames as `func@file:line` (symbolized) or `func+0xoff`.

    Including the source line keeps two distinct defects inside one function
    apart -- which is exactly what happened in legacy_parse_scope here -- while
    the function name alone would merge them.
    """
    frames = []
    for line in report.splitlines():
        m = FRAME_RE.match(line)
        if not m:
            continue
        fn = m.group(2).strip()
        if NOISE_RE.search(fn):
            continue
        if m.group(3) and m.group(4):
            frames.append(f"{fn}@{m.group(3)}:{m.group(4)}")
        else:
            # No line info: keep whatever offset the report offered.
            off = re.search(r"\+0x([0-9a-fA-F]+)", line)
            frames.append(f"{fn}+0x{off.group(1)}" if off else fn)
    return frames


def classify(report: str) -> tuple[str, list[str], str]:
    kind = "unknown"
    detail = ""

    m = ERROR_RE.search(report)
    if m:
        which, msg = m.group(1), m.group(2).strip()
        kind = {"AddressSanitizer": "asan",
                "UndefinedBehaviorSanitizer": "ubsan",
                "libFuzzer": "assert"}.get(which, "other")
        detail = msg.splitlines()[0][:160].strip()
    else:
        m = SUMMARY_RE.search(report)
        if m:
            kind = "assert" if "libFuzzer" in m.group(1) else "other"
            detail = m.group(2).strip()[:160]

    return kind, parse_frames(report), detail


def fingerprint(c: Crash) -> str:
    """Class key: sanitizer kind plus the top frames in our own code.

    The ASan detail string is intentionally excluded: it contains faulting
    addresses and allocation sizes, which differ between two instances of the
    same root cause.
    """
    core = "|".join(c.frames[:FRAMES_PER_CLASS]) or "noframes"
    return f"{c.kind}:{core}"


def classify_one(binary: str, path: str, timeout: int) -> Crash:
    c = Crash(path=path, sha=sha256_file(path), size=os.path.getsize(path))
    rc, report = run_binary(binary, path, timeout=timeout)
    # A clean exit means the input no longer triggers anything.
    c.exit_code = rc
    c.kind, c.frames, c.detail = classify(report)
    # rc == 0 is the only definitive "did not crash" signal. A timeout (124)
    # is a separate class of problem and must be kept as a live finding.
    c.reproduces = rc != 0
    c.fingerprint = fingerprint(c)
    return c


def minimize(binary: str, sample: str, out_path: str, timeout: int, budget: int) -> bool:
    rc, _ = run_binary(
        binary, sample,
        extra=["-minimize_crash=1", f"-max_total_time={budget}",
               f"-timeout={timeout}", f"-exact_artifact_path={out_path}"],
        timeout=budget + 60,
    )
    return os.path.exists(out_path) and os.path.getsize(out_path) > 0


def slug(fp: str) -> str:
    """Short, stable, filesystem-friendly class name.

    The full fingerprint (function names + file:line) lives in the report and
    summary.json; the file name only needs to be unique and greppable, so it is
    the sanitizer kind, the top frame's function, and 8 hex digits.
    """
    kind, _, rest = fp.partition(":")
    first = rest.split("|")[0] if rest else ""
    func = first.split("@")[0].split("+")[0] or "unknown"
    func = re.sub(r"[^A-Za-z0-9_]+", "_", func).strip("_")[:40] or "unknown"
    digest = hashlib.sha1(fp.encode()).hexdigest()[:8]
    return f"{kind}-{func}-{digest}"


def write_report(path: str, cls: str, fp: str, rep: Crash, members: list[Crash],
                 stored_rel: str | None) -> None:
    live = sum(1 for m in members if m.reproduces)
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# crash class `{cls}`\n\n")
        f.write(f"- fingerprint: `{fp}`\n")
        f.write(f"- sanitizer: {rep.kind}\n")
        f.write(f"- report detail: {rep.detail or '(none)'}\n")
        f.write(f"- frames: {' <- '.join(rep.frames[:FRAMES_DISPLAY]) or '(none)'}\n")
        f.write(f"- artifacts in class: {len(members)} ({live} live, "
                f"{len(members) - live} stale)\n")
        f.write(f"- representative: `{os.path.basename(rep.path)}` "
                f"(sha256 {rep.sha[:16]}..., {rep.size} bytes)\n")
        if stored_rel:
            f.write(f"- minimized sample: `{stored_rel}` "
                    f"({rep.minimized_size} bytes, down from {rep.size})\n")
        else:
            f.write("- minimized sample: n/a (did not reproduce)\n")
        f.write("\n## reproducer\n\n```sh\n")
        f.write(f"$(BINARY) {stored_rel or '<sample>'}\n")
        f.write("```\n\n## members\n\n")
        # A class can hold thousands of artifacts; the report is a summary, and
        # the full list is recoverable from summary.json and the crash dir.
        for m in members[:25]:
            f.write(f"- `{os.path.basename(m.path)}` sha256={m.sha[:16]} "
                    f"reproduces={'yes' if m.reproduces else 'no'}\n")
        if len(members) > 25:
            f.write(f"- ... and {len(members) - 25} more artifacts\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--crashes", required=True)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--regression", required=True)
    ap.add_argument("--artifacts", required=True)
    ap.add_argument("--timeout", type=int, default=30, help="per-input seconds")
    ap.add_argument("--minimize-budget", type=int, default=60,
                    help="seconds libFuzzer may spend per class")
    ap.add_argument("--max-artifacts", type=int, default=20000,
                    help="safety cap on artifacts read in one run")
    ap.add_argument("--no-minimize", action="store_true",
                    help="skip minimization (fast inventory only)")
    ap.add_argument("--jobs", type=int, default=min(8, (os.cpu_count() or 2)),
                    help="parallel replay workers (default: min(8, cpus))")
    args = ap.parse_args()

    triage_dir = os.path.join(args.artifacts, "triage")
    workdir = os.path.join(args.artifacts, "minimized")
    os.makedirs(triage_dir, exist_ok=True)
    os.makedirs(workdir, exist_ok=True)
    os.makedirs(args.regression, exist_ok=True)

    if not os.path.isdir(args.crashes):
        print(f"no crash directory at {args.crashes}; nothing to triage")
        write_index(triage_dir, args.regression)
        return 0

    names = sorted(n for n in os.listdir(args.crashes)
                   if os.path.isfile(os.path.join(args.crashes, n))
                   and not n.startswith("."))
    if not names:
        print("no crash artifacts: nothing to triage")
        write_index(triage_dir, args.regression)
        return 0
    if len(names) > args.max_artifacts:
        print(f"note: reading first {args.max_artifacts} of {len(names)} artifacts")
        names = names[:args.max_artifacts]

    print(f"phase 1: replaying {len(names)} artifact(s) with {args.jobs} workers")
    paths = [os.path.join(args.crashes, n) for n in names]
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        crashes = list(pool.map(
            lambda path: classify_one(args.binary, path, args.timeout), paths))

    groups: dict[str, list[Crash]] = {}
    for c in crashes:
        groups.setdefault(c.fingerprint, []).append(c)

    print(f"phase 2: {len(groups)} distinct class(es); minimizing one each")
    summary = []
    for fp, members in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        live = [c for c in members if c.reproduces]
        rep = live[0] if live else members[0]
        cls = slug(fp)

        accepted = False
        if live and not args.no_minimize and rep.size > 0:
            min_name = f"min-{cls}.tlv"
            min_path = os.path.join(workdir, min_name)
            if minimize(args.binary, rep.path, min_path, args.timeout,
                        args.minimize_budget):
                # libFuzzer's minimizer only promises "some crash", not "this
                # crash". A 15-byte sample that trips a *different* bug is
                # worthless as a regression test for this class, so re-classify
                # and reject any drift.
                rc, report = run_binary(args.binary, min_path, timeout=args.timeout)
                mkind, mframes, mdetail = classify(report)
                mfp = fingerprint(Crash(path=min_path, sha="", size=0,
                                        kind=mkind, frames=mframes,
                                        detail=mdetail))
                if rc != 0 and mfp == fp:
                    rep.minimized_path = min_path
                    rep.minimized_size = os.path.getsize(min_path)
                    rep.minimized_reproduces = True
                    accepted = True
                elif rc != 0:
                    print(f"    reject minimized {cls}: class drifted "
                          f"{fp[:32]} -> {mfp[:32]}")
                    try:
                        os.unlink(min_path)
                    except OSError:
                        pass

        stored_rel = None
        if not accepted and live and not args.no_minimize:
            # Fall back to the smallest raw artifact that still reproduces
            # this exact class. Raw artifacts are unminimized and larger, but
            # they are known to hit the bug being recorded.
            smallest = min(live, key=lambda c: c.size)
            rep.minimized_path = smallest.path
            rep.minimized_size = smallest.size
            rep.minimized_reproduces = True
            print(f"    fallback {cls}: using raw artifact "
                  f"{os.path.basename(smallest.path)} ({smallest.size}B)")

        if rep.minimized_reproduces and rep.minimized_path:
            # Flat layout: libFuzzer does not recurse into corpus subdirectories,
            # so the class name is a filename prefix instead of a directory.
            os.makedirs(args.regression, exist_ok=True)
            dst = os.path.join(args.regression, cls + ".tlv")
            shutil.copyfile(rep.minimized_path, dst)
            stored_rel = os.path.relpath(dst)

        write_report(os.path.join(triage_dir, cls + ".md"), cls, fp, rep,
                     members, stored_rel)

        summary.append({
            "class": cls,
            "fingerprint": fp,
            "kind": rep.kind,
            "detail": rep.detail,
            "frames": rep.frames[:FRAMES_DISPLAY],
            "artifacts": len(members),
            "live": len(live),
            "reproduces": bool(live),
            "sample": stored_rel,
            "original_size": rep.size,
            "minimized_size": rep.minimized_size,
            "minimized_reproduces": rep.minimized_reproduces,
        })

    with open(os.path.join(triage_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    write_index(triage_dir, args.regression)

    live_classes = 0
    for s in summary:
        status = "LIVE" if s["reproduces"] else "STALE"
        print(f"  [{status}] {s['class']}: {s['artifacts']} artifact(s) "
              f"-> {s['sample'] or 'n/a'} ({s['minimized_size']}B)")
        if s["reproduces"]:
            live_classes += 1
    print(f"triaged {len(crashes)} artifact(s) into {len(summary)} class(es) "
          f"({live_classes} live)")

    # Exit code 2 means "there are reproducible crashes in this build", so a
    # Makefile or CI step fails loudly instead of a human having to read logs.
    return 2 if live_classes else 0


def write_index(triage_dir: str, regression: str) -> None:
    samples = sorted(os.listdir(regression)) if os.path.isdir(regression) else []
    lines = ["# regression corpus index", "",
             f"{len(samples)} sample(s) in `{regression}`:", ""]
    for s in samples:
        lines.append(f"- `{os.path.join(regression, s)}`")
    with open(os.path.join(triage_dir, "INDEX.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"index: {len(samples)} sample(s) in {regression}")


if __name__ == "__main__":
    raise SystemExit(main())
