#!/usr/bin/env python3
"""Time queries of the pcapsql DuckDB extension (or any command) and print one line per point.

    bench.py --duckdb <duckdb shell> --extension <pcapsql.duckdb_extension> [options] <plan>...

A plan is a text file, one point per line, fields separated by tabs:

    label <TAB> threads <TAB> setup <TAB> query

`threads` is one number or several separated by commas (a point for each). `setup` is SQL run
before the timed statement in the same process (`SET pcapsql_parallel_scan = false`), or empty.
`query` is one SQL statement, timed by the shell's own `.timer`, so that starting the shell and
loading the extension are not in the number. `$NAME` in setup and query is replaced from the
environment and from `--define NAME=value`. Lines that are empty or start with `#` are skipped.

A line whose threads field is `cmd` is a shell command instead of a query (the setup field is
ignored): its time is the wall-clock time of the process. That is how another engine is timed
on the same files.

Each point is run `--warmup` times (default 1) and then `--runs` times (default 5). Output, tab
separated: label, threads, median, minimum and maximum seconds, median CPU seconds (user + system,
of the statement as the shell reports them, or of the process for a command), the largest peak
resident set of the runs in MiB (of the whole shell process), and the start of the statement's
output, so that a count can be checked against another point's.

Before each point the script waits until the machine is idle (less than `--busy` percent of the
CPU time of half a second in use, default 5), since a number taken beside another job is not
worth recording. Queries that return many rows should be written as aggregates over them
(`SELECT count(COLUMNS(*)) FROM ...`): the shell would otherwise be timed rendering the rows.
"""

import argparse
import os
import re
import resource
import statistics
import subprocess
import sys
import time


def cpu_times():
    with open("/proc/stat") as stat:
        fields = [int(x) for x in stat.readline().split()[1:]]
    idle = fields[3] + fields[4]
    return sum(fields), idle


def wait_until_idle(busy_percent, limit=300.0):
    """Returns the busy share last seen, once it is under the threshold or the limit is over."""
    start = time.monotonic()
    while True:
        total0, idle0 = cpu_times()
        time.sleep(0.5)
        total1, idle1 = cpu_times()
        busy = 100.0 * (1.0 - (idle1 - idle0) / max(1, total1 - total0))
        if busy < busy_percent or time.monotonic() - start > limit:
            return busy


def run(argv, shell=False):
    """Runs a process to its end. Returns its wall-clock seconds, the CPU seconds and the peak
    RSS in MiB of all children so far (`children_usage`), and what it wrote."""
    start = time.monotonic()
    process = subprocess.Popen(
        argv, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    out, err = process.communicate()
    wall = time.monotonic() - start
    # communicate() has reaped the child, so its usage is in the children's total: a sum for
    # the CPU time, a maximum for the peak. A fresh interpreter per point (see main) keeps
    # points apart.
    usage = children_usage()
    if process.returncode != 0:
        what = argv if shell else argv[-1]
        sys.exit(f"bench: failed ({process.returncode}): {what}\n{out}\n{err}")
    return wall, usage, out, err


def children_usage():
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime, usage.ru_maxrss / 1024.0


TIMER = re.compile(r"Run Time \(s\): real ([0-9.]+) user ([0-9.]+) sys ([0-9.]+)")


def one_point(args, label, threads, setup, query):
    """Runs one point in this process (a child of the driver) and prints its line."""
    walls, cpus, peaks, shown = [], [], [], ""
    cpu_before = 0.0
    for i in range(args.warmup + args.runs):
        if threads == "cmd":
            wall, (cpu_total, peak), out, _ = run(query, shell=True)
            cpu = cpu_total - cpu_before
        else:
            load = f"LOAD '{args.extension}'; SET threads = {threads}; {setup}"
            argv = [args.duckdb, "-unsigned", "-no-agent", "-csv", "-noheader"]
            argv += ["-cmd", load, "-cmd", ".timer on", "-c", query]
            _, (cpu_total, peak), out, err = run(argv)
            timers = TIMER.findall(out + err)
            if not timers:
                sys.exit(f"bench: no timer line for {label}:\n{out}\n{err}")
            wall = float(timers[-1][0])
            cpu = float(timers[-1][1]) + float(timers[-1][2])
            out = TIMER.sub("", out)
        cpu_before = cpu_total
        if i >= args.warmup:
            walls.append(wall)
            cpus.append(cpu)
            peaks.append(peak)
        shown = " ".join(out.split())[:60]
    print(
        f"{label}\t{threads}\t{statistics.median(walls):.3f}\t{min(walls):.3f}\t{max(walls):.3f}"
        f"\t{statistics.median(cpus):.3f}\t{max(peaks):.0f}\t{shown}",
        flush=True,
    )


def substitute(text, defines):
    return re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)", lambda m: defines.get(m.group(1), m.group(0)), text)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--duckdb", default="duckdb")
    parser.add_argument("--extension", default="build/release/pcapsql.duckdb_extension")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--busy", type=float, default=5.0)
    parser.add_argument("--define", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--point", nargs=4, help=argparse.SUPPRESS)
    parser.add_argument("plans", nargs="*")
    args = parser.parse_args()
    args.extension = os.path.abspath(args.extension)

    if args.point:
        one_point(args, *args.point)
        return

    defines = dict(os.environ)
    defines.update(d.split("=", 1) for d in args.define)
    print("label\tthreads\tmedian_s\tmin_s\tmax_s\tcpu_s\tpeak_rss_mib\tresult", flush=True)
    for plan in args.plans:
        with open(plan) as lines:
            for line in lines:
                line = line.rstrip("\n")
                if not line.strip() or line.startswith("#"):
                    continue
                fields = line.split("\t")
                if len(fields) != 4:
                    sys.exit(f"bench: {plan}: expected 4 tab-separated fields: {line!r}")
                label, threads, setup, query = (substitute(f, defines) for f in fields)
                for count in threads.split(","):
                    busy = wait_until_idle(args.busy)
                    if busy >= args.busy:
                        print(f"# machine busy ({busy:.0f}%) before the next point", flush=True)
                    # A process per point: the peak RSS of children is a running maximum.
                    point = [sys.executable, os.path.abspath(__file__)]
                    point += ["--duckdb", args.duckdb, "--extension", args.extension]
                    point += ["--runs", str(args.runs), "--warmup", str(args.warmup)]
                    point += ["--point", label, count.strip(), setup, query]
                    if subprocess.run(point).returncode != 0:
                        sys.exit(1)


if __name__ == "__main__":
    main()
