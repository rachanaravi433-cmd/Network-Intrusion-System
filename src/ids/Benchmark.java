package ids;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

/**
 * Aho-Corasick vs. naive (one pass per signature) on generated payloads.
 *
 * Experiment A: payload length M grows, number of signatures K fixed.
 * Experiment B: K grows, M fixed.
 * Experiment C: adversarial input (payload "aaaa...", signatures "aaa...ab") that
 *               hits the naive matcher's worst case.
 *
 * Each timing is the median of 3 runs after a JIT warm-up. Results are also
 * written to a CSV file so they can be charted for the project report.
 */
public final class Benchmark {

    private static final int RUNS = 3;
    private static final String HEADER = String.format("%-4s %10s %7s %10s %12s %12s %9s %10s %s",
            "exp", "M(chars)", "K(sigs)", "build(ms)", "AC scan(ms)", "naive(ms)", "speedup", "AC ns/char", "matches");

    public static void run(PrintStream out, String csvPath) {
        PrintWriter csv = null;
        try {
            csv = new PrintWriter(new FileWriter(csvPath));
            csv.println("experiment,M,K,build_ms,ac_scan_ms,naive_ms,speedup,ac_ns_per_char,matches_ac,matches_naive");
        } catch (IOException e) {
            out.println("(could not write " + csvPath + ": " + e.getMessage() + ")");
            csv = null;
        }

        out.println("Warming up the JVM...");
        warmUp();

        out.println();
        out.println("Experiment A: payload length grows, K = 100 signatures");
        out.println(HEADER);
        for (int m : new int[] {10000, 100000, 1000000, 5000000}) {
            Random rnd = new Random(42);
            List<String> sigs = randomSignatures(100, rnd);
            measure("A", sigs, randomPayload(m, sigs, rnd), out, csv);
        }

        out.println();
        out.println("Experiment B: number of signatures grows, M = 500,000 characters");
        out.println(HEADER);
        for (int k : new int[] {10, 100, 500, 1000, 2000}) {
            Random rnd = new Random(42);
            List<String> sigs = randomSignatures(k, rnd);
            measure("B", sigs, randomPayload(500000, sigs, rnd), out, csv);
        }

        out.println();
        out.println("Experiment C: adversarial input (payload = aaaa..., signatures = aaa...ab), K = 50, M = 200,000");
        out.println(HEADER);
        List<String> adversarial = new ArrayList<String>();
        for (int i = 0; i < 50; i++) {
            StringBuilder sb = new StringBuilder();
            for (int j = 0; j < 10 + i; j++) {
                sb.append('a');
            }
            sb.append('b');
            adversarial.add(sb.toString());
        }
        char[] as = new char[200000];
        Arrays.fill(as, 'a');
        measure("C", adversarial, new String(as), out, csv);

        out.println();
        out.println("Reading the results:");
        out.println(" - A: AC ns/char stays roughly constant, so the scan is linear in M.");
        out.println(" - B: naive time grows roughly in proportion to K; the AC scan time grows far more slowly.");
        out.println("      That slow growth is a memory effect: more signatures means a bigger table (states x 128 ints)");
        out.println("      that no longer fits in the CPU cache. The AC step count per character does not depend on K.");
        out.println(" - C: naive hits its worst case (about M*N comparisons); AC is unaffected.");
        out.println(" - The build cost is paid once per signature change, not once per payload.");

        if (csv != null) {
            csv.close();
            out.println();
            out.println("Results saved to " + csvPath);
        }
    }

    // ------------------------------------------------------------------

    private static void measure(String exp, List<String> sigs, String payload, PrintStream out, PrintWriter csv) {
        long[] buildTimes = new long[RUNS];
        AhoCorasick ac = null;
        for (int r = 0; r < RUNS; r++) {
            ac = new AhoCorasick();
            for (String s : sigs) {
                ac.addSignature(s);
            }
            long t0 = System.nanoTime();
            ac.build();
            buildTimes[r] = System.nanoTime() - t0;
        }
        PayloadScanner scanner = new PayloadScanner(ac);
        NaiveMatcher naive = new NaiveMatcher(ac.getSignatures());

        long[] acTimes = new long[RUNS];
        long[] naiveTimes = new long[RUNS];
        int acCount = 0;
        int naiveCount = 0;
        for (int r = 0; r < RUNS; r++) {
            long t0 = System.nanoTime();
            acCount = scanner.findAll(payload).size();
            acTimes[r] = System.nanoTime() - t0;

            t0 = System.nanoTime();
            naiveCount = naive.findAll(payload).size();
            naiveTimes[r] = System.nanoTime() - t0;
        }

        double buildMs = median(buildTimes) / 1e6;
        double acMs = median(acTimes) / 1e6;
        double naiveMs = median(naiveTimes) / 1e6;
        double speedup = naiveMs / acMs;
        double nsPerChar = median(acTimes) / (double) payload.length();
        String same = (acCount == naiveCount) ? (acCount + " (equal)") : ("MISMATCH " + acCount + " vs " + naiveCount);

        out.println(String.format("%-4s %10d %7d %10.2f %12.2f %12.2f %8.1fx %10.2f %s",
                exp, payload.length(), sigs.size(), buildMs, acMs, naiveMs, speedup, nsPerChar, same));
        if (csv != null) {
            csv.println(String.format("%s,%d,%d,%.3f,%.3f,%.3f,%.2f,%.3f,%d,%d",
                    exp, payload.length(), sigs.size(), buildMs, acMs, naiveMs, speedup, nsPerChar,
                    acCount, naiveCount));
        }
    }

    private static void warmUp() {
        Random rnd = new Random(1);
        List<String> sigs = randomSignatures(50, rnd);
        String payload = randomPayload(100000, sigs, rnd);
        AhoCorasick ac = new AhoCorasick();
        for (String s : sigs) {
            ac.addSignature(s);
        }
        PayloadScanner sc = new PayloadScanner(ac);
        NaiveMatcher nv = new NaiveMatcher(ac.getSignatures());
        int sink = 0;
        for (int i = 0; i < 15; i++) {
            sink += sc.findAll(payload).size();
            sink += nv.findAll(payload).size();
        }
        if (sink == -1) {
            System.out.println(sink); // never true; stops the JIT from discarding the work
        }
    }

    private static long median(long[] values) {
        long[] copy = values.clone();
        Arrays.sort(copy);
        return copy[copy.length / 2];
    }

    /** k distinct random lower-case signatures, 6 to 14 letters long. */
    static List<String> randomSignatures(int k, Random rnd) {
        Set<String> set = new LinkedHashSet<String>();
        while (set.size() < k) {
            int len = 6 + rnd.nextInt(9);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < len; i++) {
                sb.append((char) ('a' + rnd.nextInt(26)));
            }
            set.add(sb.toString());
        }
        return new ArrayList<String>(set);
    }

    /** Random letters and spaces, with a signature planted roughly every 5000 characters. */
    static String randomPayload(int m, List<String> sigs, Random rnd) {
        char[] buf = new char[m];
        for (int i = 0; i < m; i++) {
            buf[i] = (rnd.nextInt(8) == 0) ? ' ' : (char) ('a' + rnd.nextInt(26));
        }
        int plants = m / 5000;
        for (int p = 0; p < plants; p++) {
            String sig = sigs.get(rnd.nextInt(sigs.size()));
            if (sig.length() < m) {
                int pos = rnd.nextInt(m - sig.length());
                sig.getChars(0, sig.length(), buf, pos);
            }
        }
        return new String(buf);
    }
}
