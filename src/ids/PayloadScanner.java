package ids;

import java.util.ArrayList;
import java.util.List;

/**
 * Scans a payload once, left to right, and reports every signature occurrence
 * (including overlapping and nested ones).
 *
 * Per character: one table lookup to move to the next state, then follow the
 * dictionary links of that state. Every step of the inner loop reports one
 * real match, so total work is O(M + Z).
 */
public final class PayloadScanner {

    private final AhoCorasick automaton;

    public PayloadScanner(AhoCorasick automaton) {
        this.automaton = automaton;
    }

    /** Scans and measures the scan time (the automaton is built before timing starts). */
    public ScanResult scan(String payload) {
        automaton.ensureBuilt();
        String text = (payload == null) ? "" : payload;
        long t0 = System.nanoTime();
        List<Match> matches = findAll(text);
        long elapsed = System.nanoTime() - t0;
        return new ScanResult(text, matches, elapsed);
    }

    /** The core loop. Matches come out ordered by end position, longest signature first. */
    public List<Match> findAll(String payload) {
        automaton.ensureBuilt();
        List<Match> result = new ArrayList<Match>();
        int state = Trie.ROOT;

        for (int i = 0; i < payload.length(); i++) {
            int sym = Trie.symbol(payload.charAt(i));
            if (sym < 0) {
                state = Trie.ROOT; // non-ASCII can never be part of a signature
                continue;
            }
            state = automaton.transition(state, sym);

            for (int node = automaton.firstOutput(state);
                 node != Trie.ROOT;
                 node = automaton.nextOutput(node)) {
                String sig = automaton.signatureAt(node);
                result.add(new Match(sig, i - sig.length() + 1, i));
            }
        }
        return result;
    }
}
