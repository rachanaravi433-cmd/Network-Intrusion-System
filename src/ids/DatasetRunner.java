package ids;

/**
 * Runs automated tests over the built-in Dataset.
 * Can be run independently or called from Main.java.
 */
public final class DatasetRunner {

    public static void main(String[] args) {
        boolean verbose = args.length > 0 && args[0].equals("-v");

        AhoCorasick automaton = new AhoCorasick();

        for (String signature : Dataset.SIGNATURES) {
            automaton.addSignature(signature);
        }

        run(automaton, verbose);
    }

    /**
     * Runs the dataset tests using the supplied automaton.
     * This method can be called directly from Main.java.
     */
    public static void run(AhoCorasick automaton, boolean verbose) {

        PayloadScanner scanner = new PayloadScanner(automaton);

        int flagged = 0;
        int totalMatches = 0;
        int wrong = 0;
        long nanos = 0;

        System.out.println();
        System.out.println("======= AUTOMATED DATASET TESTING =======");

        for (int i = 0; i < Dataset.PAYLOADS.length; i++) {

            String payload = Dataset.PAYLOADS[i];
            ScanResult result = scanner.scan(payload);

            nanos += result.getScanNanos();
            totalMatches += result.matchCount();

            if (result.isDetected()) {
                flagged++;
            }

            if (result.matchCount() != Dataset.EXPECTED[i]) {
                wrong++;

                System.out.println(
                        "MISMATCH line " + (i + 1)
                        + ": expected " + Dataset.EXPECTED[i]
                        + ", got " + result.matchCount());
            }

            if (verbose && result.isDetected()) {
                System.out.println(
                        "Line " + (i + 1) + ": " + payload);

                for (Match match : result.sortedMatches()) {
                    System.out.println(
                            "    " + match.getSignature()
                            + " [" + match.getStart()
                            + ".." + match.getEnd() + "]");
                }
            }
        }

        System.out.println("-----------------------------------------");
        System.out.println("Signatures      : "
                + automaton.signatureCount());
        System.out.println("Automaton states: "
                + automaton.stateCount());
        System.out.println("Payloads        : "
                + Dataset.PAYLOADS.length);
        System.out.println("Flagged         : " + flagged);
        System.out.println("Clean           : "
                + (Dataset.PAYLOADS.length - flagged));
        System.out.println("Total matches   : " + totalMatches);

        System.out.printf(
                "Total scan time : %.3f ms%n",
                nanos / 1000000.0);

        if (wrong == 0) {
            System.out.println(
                    "RESULT: ALL " + Dataset.PAYLOADS.length
                    + " LINES CORRECT");
        } else {
            System.out.println(
                    "RESULT: " + wrong + " LINE(S) WRONG");
        }

        System.out.println("=========================================");
    }
}
