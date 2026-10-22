<<<<<<< HEAD
# Network Intrusion Detection System Using Multi-Pattern Payload Matching

A signature-based intrusion detection **prototype** built on the **Aho-Corasick automaton** (a trie with failure links), written in Java for the Advanced DSA lab.

It scans a text *payload* once, left to right, and reports **every** configured signature that occurs in it (including overlapping and nested ones), with positions. A match does not prove an attack: it flags text for further investigation. Payloads are simulated strings, not captured network traffic.

## Project layout

| File | Role |
|---|---|
| `src/ids/Trie.java` | Array-based trie over ASCII (128 columns); node = integer id |
| `src/ids/AhoCorasick.java` | Signature database (add/remove) and `build()`: BFS for failure links, dictionary links and the full transition table |
| `src/ids/PayloadScanner.java` | The scan loop: one table lookup per character, then follow dictionary links to report matches |
| `src/ids/Match.java`, `ScanResult.java` | Result types |
| `src/ids/NaiveMatcher.java` | Baseline: one brute-force pass per signature |
| `src/ids/Benchmark.java` | Aho-Corasick vs naive on growing payloads and signature sets |
| `src/ids/Main.java` | Command-line dashboard |
| `src/ids/Tests.java` | Self-contained tests, including a randomised cross-check against the naive matcher |

## Build and run

Requires JDK 8 or newer.

```bash
javac -d out src/ids/*.java      # compile
java -cp out ids.Main            # interactive dashboard
java -cp out ids.Main demo       # run the sample payloads
java -cp out ids.Main benchmark  # performance comparison (about 30 s), writes benchmark_results.csv
java -cp out ids.Tests           # run the tests
```

In an IDE (IntelliJ, VS Code, Eclipse), mark `src` as the source folder and run `ids.Main`.

Example output (positions are 0-based):

```
Payload            : Request: UNION SELECT username FROM users
Matching Signature : UNION SELECT
Starting Position  : 9  (0-based)
Ending Position    : 20
Detection Status   : SIGNATURE DETECTED
Total matches      : 1
```

## How it works

1. **Trie.** All signatures are inserted into a trie, so common prefixes are stored once.
2. **Failure links (BFS).** For each trie node `u` (the string spelled by the path to it), `fail[u]` is the node for the longest proper suffix of that string that is also in the trie. It is computed level by level with a BFS, because `fail[u]` is always shallower than `u`.
3. **Full transition table.** Missing edges are filled in with the transition of the failure state, so while scanning there is exactly one table lookup per character and never a failure-chain walk.
4. **Dictionary links.** `dictLink[u]` points to the nearest node on `u`'s failure chain where a signature ends. Following these links visits only real matches, so reporting all overlapping matches costs O(1) per match.
5. **Scan.** Keep one state. For each payload character, move to `next[state][c]`, then report the signature ending at that state (if any) and everything reachable through `dictLink`.

Worked example: signatures `he, she, his, hers`, payload `ushers`.

| State | String | Failure link | Signature ends here |
|---|---|---|---|
| 1 | h | root | |
| 2 | he | root | he |
| 3 | s | root | |
| 4 | sh | h (1) | |
| 5 | she | he (2) | she (and `he` via dictLink) |
| 6 | hi | root | |
| 7 | his | s (3) | his |
| 8 | her | root | |
| 9 | hers | s (3) | hers |

Scanning `ushers`: `u` stays at the root; `s` goes to state 3; `h` goes to 4; `e` goes to 5, which reports `she` at index 1 and, through the dictionary link, `he` at index 2; `r` goes to 8 (via the failure state `he`); `s` goes to 9, which reports `hers` at index 2.

## Design choices and trade-offs

| Choice | Why | Trade-off |
|---|---|---|
| Child table `int[128]` per node | O(1) transition, simplest and fastest | Memory is about (N+1) x 128 x 4 bytes; a hash map or linked child list would use less memory but is slower per step |
| Nodes as `int` ids in parallel arrays (`fail`, `dictLink`, `sigIndexAt`) | No object per node, cache-friendly | Less readable than a `Node` class |
| Full automaton (missing edges filled in) | Scan does one lookup per character, so scan time is exactly O(M + Z) | Slightly more work in `build()` |
| Dictionary links | Report overlaps in O(1) per match | One extra int array |
| Rebuild on signature change | Simple and correct; the signature list changes rarely compared with payload volume | Cost O(N x 128) per change; incremental update is much more complex |
| Case-insensitive matching (A-Z folded) | `union select` and `UNION SELECT` are the same attack | Signatures cannot be case-sensitive |
| Non-ASCII payload character resets to the root | No signature contains one, so no match can span it | Signatures must be ASCII |

## Complexity

Let N = total length of all signatures, M = payload length, Z = number of matches, and sigma = alphabet size (128, a constant).

| Operation | Time |
|---|---|
| Build trie | O(N) (each node allocates a row of sigma entries: O(N x sigma)) |
| BFS: failure links, dictionary links, full table | O(N x sigma) = O(N) for constant sigma, since each node is dequeued once |
| Scan one payload | O(M + Z) |
| Overall | O(N + M + Z) for constant sigma |
| Space | O(N x sigma) |
| Naive (one pass per signature) | O(M x N) worst case |

Why the scan is O(M + Z): with the full table, each character costs one array lookup (O(1)), and every iteration of the dictionary-link loop reports one real match. (Without the full table, the classic argument is amortised: the matched depth rises by at most 1 per character and every failure step lowers it, so total failure steps are at most M.)

Sorting matches by position for display costs O(Z log Z) and is not part of the scan.

## Benchmark

`java -cp out ids.Main benchmark` runs three experiments (median of 3 runs after a warm-up) and writes `benchmark_results.csv`:

- **A:** payload length grows (10k to 5M characters), 100 signatures. Aho-Corasick time per character stays roughly constant, so the scan is linear in M.
- **B:** signatures grow (10 to 2000), 500k-character payload. Naive time grows roughly in proportion to K; Aho-Corasick grows far more slowly (a larger table causes more CPU cache misses; the work per character does not depend on K).
- **C:** adversarial input (`aaaa...` against `aaa...ab`) that triggers the naive matcher's worst case.

TODO (team): paste the table from your own machine here. Timings differ between computers.

## Limitations

- This is a signature-based prototype, not a production IDS. It cannot detect attacks that do not contain a configured signature, and an attacker can evade plain-text signatures with encoding or obfuscation.
- A match can be a false positive (for example, a blog post that contains `DROP TABLE`).
- Matching is on single payloads. Signatures split across two separate payloads are not detected (the automaton state could be carried between chunks as an extension).


# Network-Intrusion-System
This project is an advanced Data Structures and Algorithms (DSA) implementation of a Network Intrusion Detection System (NIDS) designed to scan incoming web traffic for malicious payloads.
>>>>>>> fd4ec6e424cd5bbf5a8330a663513cf3accfc412
