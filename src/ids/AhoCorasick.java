package ids;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Aho-Corasick automaton: a trie plus failure links, built with a BFS.
 *
 * Holds the signature database (add / remove) and builds the automaton from it.
 * The automaton is rebuilt lazily whenever the signature list has changed.
 *
 * Arrays indexed by node id:
 *   fail[u]     - longest proper suffix of u's string that is also a trie node
 *   dictLink[u] - nearest node on u's failure chain where a signature ends
 *                 (0 = none). Following dictLink visits only real matches, so
 *                 reporting all overlapping matches costs O(1) per match.
 */
public final class AhoCorasick {

    private final List<String> signatures = new ArrayList<String>();
    private final Set<String> seen = new HashSet<String>(); // case-folded, for duplicates

    private Trie trie;
    private int[] fail;
    private int[] dictLink;
    private boolean dirty = true;

    // ------------------------------------------------------------------
    // Signature management
    // ------------------------------------------------------------------

    /** @return true if added, false if it was already present (ignoring case). */
    public boolean addSignature(String signature) {
        if (signature == null || signature.isEmpty()) {
            throw new IllegalArgumentException("Signature must not be empty");
        }
        for (int i = 0; i < signature.length(); i++) {
            if (signature.charAt(i) >= Trie.ALPHABET) {
                throw new IllegalArgumentException("Signature must be plain ASCII: " + signature);
            }
        }
        if (!seen.add(Trie.fold(signature))) {
            return false;
        }
        signatures.add(signature);
        dirty = true;
        return true;
    }

    /** @return true if a signature was removed. */
    public boolean removeSignature(String signature) {
        if (signature == null) {
            return false;
        }
        String key = Trie.fold(signature);
        if (!seen.remove(key)) {
            return false;
        }
        for (int i = 0; i < signatures.size(); i++) {
            if (Trie.fold(signatures.get(i)).equals(key)) {
                signatures.remove(i);
                break;
            }
        }
        dirty = true;
        return true;
    }

    public List<String> getSignatures() {
        return Collections.unmodifiableList(signatures);
    }

    public int signatureCount() {
        return signatures.size();
    }

    // ------------------------------------------------------------------
    // Construction: trie, then BFS for failure links and the full transition table
    // ------------------------------------------------------------------

    public void build() {
        // 1. trie of all signatures: O(N)
        Trie t = new Trie();
        for (int i = 0; i < signatures.size(); i++) {
            t.insert(signatures.get(i), i);
        }

        int n = t.nodeCount;
        int[] f = new int[n];     // all 0 = root
        int[] d = new int[n];     // all 0 = no output link
        int[] queue = new int[n]; // each node is enqueued exactly once
        int head = 0;
        int tail = 0;

        // 2. depth 1: failure link is the root; missing root edges loop to the root
        for (int c = 0; c < Trie.ALPHABET; c++) {
            int v = t.next[Trie.ROOT][c];
            if (v == Trie.NONE) {
                t.next[Trie.ROOT][c] = Trie.ROOT;
            } else {
                f[v] = Trie.ROOT;
                queue[tail++] = v;
            }
        }

        // 3. BFS by depth: fail[u] is always shallower than u, so its row is already complete
        while (head < tail) {
            int u = queue[head++];
            int fu = f[u];
            d[u] = (t.sigIndexAt[fu] != Trie.NONE) ? fu : d[fu];

            for (int c = 0; c < Trie.ALPHABET; c++) {
                int v = t.next[u][c];
                if (v == Trie.NONE) {
                    t.next[u][c] = t.next[fu][c];   // borrow the failure state's transition
                } else {
                    f[v] = t.next[fu][c];           // failure link of the child
                    queue[tail++] = v;
                }
            }
        }

        this.trie = t;
        this.fail = f;
        this.dictLink = d;
        this.dirty = false;
    }

    /** Builds only if the signature list changed since the last build. */
    void ensureBuilt() {
        if (dirty) {
            build();
        }
    }

    // ------------------------------------------------------------------
    // Read access for PayloadScanner
    // ------------------------------------------------------------------

    int transition(int state, int symbol) {
        return trie.next[state][symbol];
    }

    /** First node (state itself or via dictLink) where a signature ends, or 0 if none. */
    int firstOutput(int state) {
        return (trie.sigIndexAt[state] != Trie.NONE) ? state : dictLink[state];
    }

    int nextOutput(int outputNode) {
        return dictLink[outputNode];
    }

    String signatureAt(int outputNode) {
        return signatures.get(trie.sigIndexAt[outputNode]);
    }

    public int stateCount() {
        ensureBuilt();
        return trie.nodeCount;
    }

    /** For teaching/debugging: failure link of a state. */
    public int failureOf(int state) {
        ensureBuilt();
        return fail[state];
    }
}
