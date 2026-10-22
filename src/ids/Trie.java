package ids;

import java.util.Arrays;

/**
 * Array-based trie (prefix tree) over the 7-bit ASCII alphabet.
 *
 * Representation: every node is an integer id (the root is 0). The children of
 * node u are stored in row next[u], an int[128], so following an edge for
 * symbol c is one array access: next[u][c].
 *
 * After AhoCorasick.build() finishes, this same table is reused as the full
 * automaton transition table (missing edges are filled in with the transition
 * of the failure state), so no extra copy of the table is needed.
 */
final class Trie {

    static final int ALPHABET = 128; // ASCII
    static final int NONE = -1;      // "no child" / "no signature ends here"
    static final int ROOT = 0;

    int[][] next;      // next[node][symbol] -> child node, or NONE
    int[] sigIndexAt;  // index of the signature that ends at node, or NONE
    int nodeCount;

    Trie() {
        next = new int[16][];
        sigIndexAt = new int[16];
        nodeCount = 0;
        newNode(); // root
    }

    private int newNode() {
        if (nodeCount == next.length) { // grow by doubling: amortised O(1)
            next = Arrays.copyOf(next, nodeCount * 2);
            sigIndexAt = Arrays.copyOf(sigIndexAt, nodeCount * 2);
        }
        int[] row = new int[ALPHABET];
        Arrays.fill(row, NONE);
        next[nodeCount] = row;
        sigIndexAt[nodeCount] = NONE;
        return nodeCount++;
    }

    /** Inserts a signature; sigIndex is remembered at its terminal node. O(length). */
    void insert(String signature, int sigIndex) {
        int node = ROOT;
        for (int i = 0; i < signature.length(); i++) {
            int sym = symbol(signature.charAt(i));
            if (sym < 0) {
                throw new IllegalArgumentException("Non-ASCII character in signature: " + signature);
            }
            if (next[node][sym] == NONE) {
                int created = newNode();
                next[node][sym] = created;
            }
            node = next[node][sym];
        }
        sigIndexAt[node] = sigIndex;
    }

    /** Lower-cases A-Z only (matching is case-insensitive). */
    static char fold(char ch) {
        return (ch >= 'A' && ch <= 'Z') ? (char) (ch + 32) : ch;
    }

    static String fold(String s) {
        char[] out = new char[s.length()];
        for (int i = 0; i < out.length; i++) {
            out[i] = fold(s.charAt(i));
        }
        return new String(out);
    }

    /**
     * Maps a character to its table column (0..127) after case folding,
     * or -1 if it is not ASCII (no signature can contain it).
     */
    static int symbol(char ch) {
        char f = fold(ch);
        return f < ALPHABET ? f : -1;
    }
}
