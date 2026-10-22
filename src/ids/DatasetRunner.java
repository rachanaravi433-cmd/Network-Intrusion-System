package ids;

/** Runs the Aho-Corasick scanner over the built-in Dataset and checks every line
 *  against the expected match count. Run: java -cp out ids.DatasetRunner [-v] */
public final class DatasetRunner {
    public static void main(String[] args) {
        boolean verbose = args.length > 0 && args[0].equals("-v");
        AhoCorasick automaton = new AhoCorasick();
        for (String s : Dataset.SIGNATURES) {
            automaton.addSignature(s);
        }
        PayloadScanner scanner = new PayloadScanner(automaton);
        int flagged = 0, totalMatches = 0, wrong = 0;
        long nanos = 0;
        for (int i = 0; i < Dataset.PAYLOADS.length; i++) {
            ScanResult r = scanner.scan(Dataset.PAYLOADS[i]);
            nanos += r.getScanNanos();
            totalMatches += r.matchCount();
            if (r.isDetected()) {
                flagged++;
            }
            if (r.matchCount() != Dataset.EXPECTED[i]) {
                wrong++;
                System.out.println("MISMATCH line " + (i + 1) + ": expected "
                        + Dataset.EXPECTED[i] + ", got " + r.matchCount());
            }
            if (verbose && r.isDetected()) {
                System.out.println("Line " + (i + 1) + ": " + Dataset.PAYLOADS[i]);
                for (Match m : r.sortedMatches()) {
                    System.out.println("    " + m.getSignature() + " [" + m.getStart() + ".." + m.getEnd() + "]");
                }
            }
        }
        System.out.println("Signatures      : " + automaton.signatureCount() + " (" + automaton.stateCount() + " states)");
        System.out.println("Payloads        : " + Dataset.PAYLOADS.length);
        System.out.println("Flagged         : " + flagged);
        System.out.println("Clean           : " + (Dataset.PAYLOADS.length - flagged));
        System.out.println("Total matches   : " + totalMatches);
        System.out.println("Total scan time : " + (nanos / 1000000.0) + " ms");
        System.out.println(wrong == 0 ? "RESULT: ALL " + Dataset.PAYLOADS.length + " LINES CORRECT"
                : "RESULT: " + wrong + " LINE(S) WRONG");
    }
}
