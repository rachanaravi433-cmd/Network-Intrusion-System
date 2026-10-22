package ids;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/**
 * Self-contained tests (no JUnit needed). Run:  java -cp out ids.Tests
 * Exit code is 0 only if every check passes.
 */
public final class Tests {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        classicExample();
        documentExamples();
        overlappingAndNested();
        suffixSignatures();
        caseInsensitive();
        duplicatesAndInvalidInput();
        emptyCases();
        boundaryMatches();
        nonAsciiPayload();
        dynamicSignatures();
        sharedPrefixStateCount();
        veryLongPayload();
        randomCrossCheck();

        System.out.println();
        System.out.println("Passed: " + passed + "   Failed: " + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }

    // ------------------------------------------------------------------ tests

    private static void classicExample() {
        AhoCorasick ac = automaton("he", "she", "his", "hers");
        check(scan(ac, "ushers"), list("she@1", "he@2", "hers@2"), "classic: ushers");
    }

    private static void documentExamples() {
        AhoCorasick ac = automaton("UNION SELECT", "DROP TABLE", "cmd.exe");

        String p1 = "Request: UNION SELECT username FROM users";
        check(scan(ac, p1), list("UNION SELECT@" + p1.indexOf("UNION")), "doc example 1");
        check(p1.indexOf("UNION") == 9, "UNION starts at index 9 (0-based)");

        String p2 = "Request: UNION SELECT data; DROP TABLE users";
        check(scan(ac, p2),
              list("UNION SELECT@" + p2.indexOf("UNION"), "DROP TABLE@" + p2.indexOf("DROP")),
              "doc example 2: two signatures in one scan");
    }

    private static void overlappingAndNested() {
        AhoCorasick ac = automaton("a", "aa", "aaa");
        List<Match> m = new PayloadScanner(ac).findAll("aaaa");
        check(m.size() == 9, "overlap: a,aa,aaa in aaaa -> 4+3+2 = 9 matches (got " + m.size() + ")");
    }

    private static void suffixSignatures() {
        AhoCorasick ac = automaton("abcd", "bc", "c");
        check(scan(ac, "abcd"), list("abcd@0", "bc@1", "c@2"), "signature that is a suffix of another");
    }

    private static void caseInsensitive() {
        AhoCorasick ac = automaton("union select");
        check(scan(ac, "x UnIoN sElEcT y"), list("union select@2"), "case-insensitive match");
    }

    private static void duplicatesAndInvalidInput() {
        AhoCorasick ac = new AhoCorasick();
        check(ac.addSignature("cmd.exe"), "first add returns true");
        check(!ac.addSignature("CMD.EXE"), "duplicate (different case) is ignored");
        check(ac.signatureCount() == 1, "duplicate not stored twice");
        check(throwsIllegalArgument(ac, ""), "empty signature rejected");
        check(throwsIllegalArgument(ac, null), "null signature rejected");
        check(throwsIllegalArgument(ac, "café"), "non-ASCII signature rejected");
    }

    private static void emptyCases() {
        AhoCorasick ac = automaton("abc");
        check(scan(ac, "").isEmpty(), "empty payload -> no matches");
        check(scan(ac, "xyz abx").isEmpty(), "no-match payload -> no matches");
        check(scan(new AhoCorasick(), "anything at all").isEmpty(), "no signatures -> no matches");
    }

    private static void boundaryMatches() {
        AhoCorasick ac = automaton("ab");
        check(scan(ac, "abxxab"), list("ab@0", "ab@4"), "match at index 0 and at the very end");
        check(scan(ac, "ababab"), list("ab@0", "ab@2", "ab@4"), "same signature repeated");
    }

    private static void nonAsciiPayload() {
        AhoCorasick ac = automaton("ab");
        check(scan(ac, "aéb").isEmpty(), "non-ASCII char between letters breaks the match");
        check(scan(ac, "éab"), list("ab@1"), "match right after a non-ASCII char");
    }

    private static void dynamicSignatures() {
        AhoCorasick ac = automaton("drop table");
        PayloadScanner sc = new PayloadScanner(ac);
        String payload = "x; DROP TABLE t; ../etc/passwd";
        check(sc.findAll(payload).size() == 1, "before adding: 1 match");
        ac.addSignature("../etc/passwd");
        check(sc.findAll(payload).size() == 2, "after adding a signature (auto rebuild): 2 matches");
        ac.removeSignature("DROP TABLE");
        check(sc.findAll(payload).size() == 1, "after removing a signature: 1 match");
        check(!ac.removeSignature("not there"), "removing an unknown signature returns false");
    }

    private static void sharedPrefixStateCount() {
        AhoCorasick ac = automaton("he", "hers");
        check(ac.stateCount() == 5, "trie shares prefixes: root,h,e,r,s = 5 states (got " + ac.stateCount() + ")");
    }

    private static void veryLongPayload() {
        char[] buf = new char[2000000];
        Arrays.fill(buf, 'a');
        AhoCorasick ac = automaton("aaa");
        int count = new PayloadScanner(ac).findAll(new String(buf)).size();
        check(count == 2000000 - 2, "2M-char payload, many overlapping matches (got " + count + ")");
    }

    /** Aho-Corasick must give exactly the same matches as the brute-force matcher. */
    private static void randomCrossCheck() {
        Random rnd = new Random(12345);
        int trials = 5000;
        int bad = 0;
        for (int t = 0; t < trials; t++) {
            int alpha = 2 + rnd.nextInt(3);
            AhoCorasick ac = new AhoCorasick();
            int k = 1 + rnd.nextInt(8);
            for (int i = 0; i < k; i++) {
                ac.addSignature(randomText(rnd, 1 + rnd.nextInt(5), alpha));
            }
            String payload = randomText(rnd, rnd.nextInt(41), alpha);

            List<Match> a = new PayloadScanner(ac).findAll(payload);
            List<Match> b = new NaiveMatcher(ac.getSignatures()).findAll(payload);
            Collections.sort(a, Match.BY_POSITION);
            Collections.sort(b, Match.BY_POSITION);
            if (!a.equals(b)) {
                bad++;
                if (bad <= 3) {
                    System.out.println("  MISMATCH sigs=" + ac.getSignatures() + " payload=\"" + payload
                            + "\" ac=" + a + " naive=" + b);
                }
            }
        }
        check(bad == 0, "random cross-check vs naive: " + trials + " trials, " + bad + " mismatches");
    }

    // ---------------------------------------------------------------- helpers

    private static AhoCorasick automaton(String... sigs) {
        AhoCorasick ac = new AhoCorasick();
        for (String s : sigs) {
            ac.addSignature(s);
        }
        return ac;
    }

    private static List<String> scan(AhoCorasick ac, String payload) {
        List<Match> m = new PayloadScanner(ac).findAll(payload);
        Collections.sort(m, Match.BY_POSITION);
        List<String> out = new ArrayList<String>();
        for (Match x : m) {
            out.add(x.toString());
        }
        return out;
    }

    private static List<String> list(String... items) {
        return Arrays.asList(items);
    }

    private static boolean throwsIllegalArgument(AhoCorasick ac, String sig) {
        try {
            ac.addSignature(sig);
            return false;
        } catch (IllegalArgumentException e) {
            return true;
        }
    }

    private static String randomText(Random rnd, int len, int alpha) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            char c = (char) ('a' + rnd.nextInt(alpha));
            if (rnd.nextInt(6) == 0) {
                c = Character.toUpperCase(c); // mix in upper case to exercise folding
            }
            sb.append(c);
        }
        return sb.toString();
    }

    private static void check(List<String> actual, List<String> expected, String name) {
        boolean ok = actual.equals(expected);
        check(ok, name + (ok ? "" : "   expected " + expected + " but got " + actual));
    }

    private static void check(boolean ok, String name) {
        if (ok) {
            passed++;
            System.out.println("  PASS  " + name);
        } else {
            failed++;
            System.out.println("  FAIL  " + name);
        }
    }
}
