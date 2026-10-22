package ids;

import java.util.ArrayList;
import java.util.List;

/**
 * Baseline: search for each signature separately with a brute-force comparison.
 * Used for correctness cross-checks and for the performance comparison.
 * Worst case O(M * N) (M = payload length, N = total signature length).
 */
public final class NaiveMatcher {

    private final String[] signatures;
    private final char[][] folded;

    public NaiveMatcher(List<String> signatureList) {
        signatures = signatureList.toArray(new String[0]);
        folded = new char[signatures.length][];
        for (int i = 0; i < signatures.length; i++) {
            folded[i] = Trie.fold(signatures[i]).toCharArray();
        }
    }

    public List<Match> findAll(String payload) {
        char[] text = Trie.fold(payload).toCharArray();
        List<Match> result = new ArrayList<Match>();

        for (int s = 0; s < signatures.length; s++) {   // one full pass per signature
            char[] p = folded[s];
            int m = p.length;
            for (int i = 0; i + m <= text.length; i++) {
                int j = 0;
                while (j < m && text[i + j] == p[j]) {
                    j++;
                }
                if (j == m) {
                    result.add(new Match(signatures[s], i, i + m - 1));
                }
            }
        }
        return result;
    }
}
