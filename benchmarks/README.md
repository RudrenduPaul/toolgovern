# Benchmarks

Two scripts, both run against the real, built `toolgovern` package (`packages/toolgovern/dist`,
the exact code a consumer of the published package would run), not against source or mocks.

```bash
npm run build                    # builds packages/toolgovern first -- both scripts import dist/
npm run bench:detection-rate
npm run bench:latency
```

Per this repo's own engineering standard (see `CLAUDE.md`), no detection-rate, false-positive-rate,
or latency number is written into any doc unless it is the literal output of one of these two
commands. The numbers below were captured by running each command three times on the same machine
and are reported as the observed range, not rounded up.

## Corpus

`corpus.ts` is a hand-labeled set of 112 tool-call cases: 63 expected-risky (true positive) and 49
expected-benign (true negative), split across all five v0.1 rule categories with at least 15 cases
per category (TG01: 29, TG02: 22, TG03: 21, TG04: 22, TG05: 18). Each category's cases include
several obfuscated/adversarial variants for the argument-obfuscation techniques documented in
`docs/security-model.md` -- base64-decode-then-execute, empty-quote-pair splitting, invisible
Unicode characters, and `$IFS`-as-space substitution -- so the detection-rate number reflects the
hardened classifier, not just the easy cases.

This is a labeled test corpus the maintainers wrote, not a sample of real-world agent traffic. It
proves the classifier behaves as intended against the specific cases in it; it is not a claim about
what fraction of real agent tool calls in the wild are risky. Extend it in `corpus.ts` -- add a
`CorpusCase` with a `label`, `expected` (`'benign'` | `'risky'`), `category` (`TG01`-`TG05`), and a
`context` built with the matching helper (`shellCtx`, `fsCtx`, `netCtx`, `credCtx`, or `tg05Case`/
`tg05ShrunkCase` for cross-agent scenarios).

## Detection rate and false-positive rate

Measured over 3 runs. The number is identical every run, since `classify()` is a pure function of
its input -- no randomness, no timing dependency.

```
$ npm run bench:detection-rate
```

| Category                               | Rule checks | Detection rate     | False-positive rate | n (risky / benign) |
| -------------------------------------- | ----------- | ------------------ | ------------------- | ------------------ |
| TG01 Shell/Process Execution Risk      | 8           | 100.0% (16/16)     | 0.0% (0/13)         | 29                 |
| TG02 Filesystem Scope Escalation       | 6           | 100.0% (13/13)     | 0.0% (0/9)          | 22                 |
| TG03 Undeclared Network Egress         | 6           | 100.0% (12/12)     | 0.0% (0/9)          | 21                 |
| TG04 Credential/Secret Access          | 6           | 100.0% (13/13)     | 0.0% (0/9)          | 22                 |
| TG05 Cross-Agent Privilege Inheritance | 5           | 100.0% (9/9)       | 0.0% (0/9)          | 18                 |
| **Overall**                            | **31**      | **100.0% (63/63)** | **0.0% (0/49)**     | **112**            |

"Detection rate" per category counts a case as caught only if a rule from _that category_ fired
(not merely if any rule anywhere fired), so one category's number cannot be inflated by a
neighboring category catching the same call for a different reason -- see the category-aware
scoring in `detection-rate.ts`.

**Read this honestly, not as a marketing number.** 100% is the correct score on a corpus the
maintainers wrote to match the rules the maintainers wrote -- it proves the classifier does what it
was designed to do on the cases tested, including the specific obfuscation techniques closed in the
security pass. It is not a claim that 100% of real-world risky tool calls will be caught; a
sufficiently novel obfuscation technique not covered here, or a call shape outside this corpus,
could still get through. See `docs/security-model.md` for what is explicitly _not_ covered (full
shell-grammar parsing, TG06/TG07 session-level anomaly detection, which are not in v0.1).

## Per-call latency (measured, 3 runs, 5,000 samples each after 200 warmup iterations)

```
$ npm run bench:latency
```

| Run       | Mean             | p50              | p95              | p99                |
| --------- | ---------------- | ---------------- | ---------------- | ------------------ |
| 1         | 7.04 us          | 6.63 us          | 9.54 us          | 16.04 us           |
| 2         | 6.74 us          | 6.50 us          | 8.92 us          | 11.46 us           |
| 3         | 6.82 us          | 6.54 us          | 9.04 us          | 12.88 us           |
| **Range** | **6.74-7.04 us** | **6.50-6.63 us** | **8.92-9.54 us** | **11.46-16.04 us** |

An earlier 3-run set on the same machine, captured right after a burst of `npm run build` /
`npm run test:coverage` invocations, measured noticeably higher (mean 23-26 us, p99 78-93 us) --
wall-clock microbenchmarks are sensitive to whatever else the machine is doing at the moment, which
is exactly why this file says "run it yourself" rather than asserting a single portable number.
The table above is the most recent measurement and is what's cited in the top-level README.

This measures `classify()` alone -- every call runs the full 31-rule pack (there is no
per-category dispatch or short-circuiting), so latency does not vary meaningfully by which category
a given call happens to belong to. It does not include the wrapped tool's own execution time, and
it does not include trace-write time (`TraceWriter.append()` is a separate, async, file-append
operation `governTool()` awaits after the classifier decision, not part of this number). All of it
runs in-process with no network round-trip, on whatever machine runs the command -- these are not
portable "the product is Xms" numbers, they are what this classifier measured on the machine that
ran it. Run it yourself on your own hardware before relying on it for a latency budget.
