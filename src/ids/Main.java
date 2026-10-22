package ids;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.List;
import java.util.Scanner;

/**
 * Command-line dashboard for the signature-based intrusion detection prototype.
 *
 *   java -cp out ids.Main              interactive menu
 *   java -cp out ids.Main demo         run the sample payloads and exit
 *   java -cp out ids.Main benchmark    run the benchmark and exit
 */
public final class Main {

    private static final String[] DEFAULT_SIGNATURES = {
        "UNION SELECT", "DROP TABLE", "../etc/passwd", "cmd.exe", "<script>", "' OR '1'='1"
    };

    private static final String[] SAMPLE_PAYLOADS = {
        "Request: UNION SELECT username FROM users",
        "Request: UNION SELECT data; DROP TABLE users",
        "GET /download?file=../../etc/passwd HTTP/1.1",
        "POST /login user=admin&comment=<script>alert(1)</script>",
        "GET /index.html HTTP/1.1 Host: example.com",
    };

    private static final String CSV_FILE = "benchmark_results.csv";

    public static void main(String[] args) {
        AhoCorasick automaton = new AhoCorasick();
        for (String s : DEFAULT_SIGNATURES) {
            automaton.addSignature(s);
        }
        PayloadScanner scanner = new PayloadScanner(automaton);

        if (args.length > 0 && args[0].equalsIgnoreCase("demo")) {
            runSamples(scanner, automaton);
            return;
        }
        if (args.length > 0 && args[0].equalsIgnoreCase("benchmark")) {
            Benchmark.run(System.out, CSV_FILE);
            return;
        }
        interactive(automaton, scanner);
    }

    // ------------------------------------------------------------------ menu

    private static void interactive(AhoCorasick automaton, PayloadScanner scanner) {
        Scanner in = new Scanner(System.in);
        while (true) {
            System.out.println();
            System.out.println("======= INTRUSION DETECTION SYSTEM =======");
            System.out.println(" 1. Scan a payload");
            System.out.println(" 2. Add a signature");
            System.out.println(" 3. Remove a signature");
            System.out.println(" 4. List signatures");
            System.out.println(" 5. Scan a text file (one payload per line)");
            System.out.println(" 6. Run sample payloads");
            System.out.println(" 7. Run benchmark (Aho-Corasick vs naive)");
            System.out.println(" 0. Exit");
            System.out.print("Choice: ");
            if (!in.hasNextLine()) {
                return;
            }
            String choice = in.nextLine().trim();

            if (choice.equals("0")) {
                System.out.println("Goodbye.");
                return;
            } else if (choice.equals("1")) {
                System.out.print("Enter payload: ");
                if (!in.hasNextLine()) {
                    return;
                }
                report(scanner.scan(in.nextLine()), automaton);
            } else if (choice.equals("2")) {
                System.out.print("New signature: ");
                if (!in.hasNextLine()) {
                    return;
                }
                addSignature(automaton, in.nextLine().trim());
            } else if (choice.equals("3")) {
                System.out.print("Signature to remove: ");
                if (!in.hasNextLine()) {
                    return;
                }
                String s = in.nextLine().trim();
                System.out.println(automaton.removeSignature(s)
                        ? "Removed. The automaton will be rebuilt on the next scan."
                        : "Signature not found.");
            } else if (choice.equals("4")) {
                listSignatures(automaton);
            } else if (choice.equals("5")) {
                System.out.print("File path: ");
                if (!in.hasNextLine()) {
                    return;
                }
                scanFile(in.nextLine().trim(), scanner, automaton);
            } else if (choice.equals("6")) {
                runSamples(scanner, automaton);
            } else if (choice.equals("7")) {
                Benchmark.run(System.out, CSV_FILE);
            } else {
                System.out.println("Invalid choice.");
            }
        }
    }

    // --------------------------------------------------------------- actions

    private static void addSignature(AhoCorasick automaton, String s) {
        try {
            if (automaton.addSignature(s)) {
                System.out.println("Added. The automaton will be rebuilt on the next scan.");
            } else {
                System.out.println("That signature already exists (case is ignored).");
            }
        } catch (IllegalArgumentException e) {
            System.out.println("Rejected: " + e.getMessage());
        }
    }

    private static void listSignatures(AhoCorasick automaton) {
        List<String> sigs = automaton.getSignatures();
        System.out.println("Signatures (" + sigs.size() + "):");
        for (int i = 0; i < sigs.size(); i++) {
            System.out.println("  " + (i + 1) + ". " + sigs.get(i));
        }
    }

    private static void runSamples(PayloadScanner scanner, AhoCorasick automaton) {
        for (String payload : SAMPLE_PAYLOADS) {
            report(scanner.scan(payload), automaton);
        }
    }

    private static void scanFile(String path, PayloadScanner scanner, AhoCorasick automaton) {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(path));
            String line;
            int lineNo = 0;
            int flagged = 0;
            while ((line = reader.readLine()) != null) {
                lineNo++;
                ScanResult r = scanner.scan(line);
                if (r.isDetected()) {
                    flagged++;
                    System.out.println("Line " + lineNo + ": " + r.matchCount() + " match(es)");
                    report(r, automaton);
                }
            }
            System.out.println("Scanned " + lineNo + " line(s); " + flagged + " flagged.");
        } catch (IOException e) {
            System.out.println("Could not read file: " + e.getMessage());
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException ignored) {
                    // nothing useful to do
                }
            }
        }
    }

    // ------------------------------------------------------------- dashboard

    private static void report(ScanResult result, AhoCorasick automaton) {
        String payload = result.getPayload();
        String shown = payload.length() > 80 ? payload.substring(0, 77) + "..." : payload;

        System.out.println();
        System.out.println("======= INTRUSION DETECTION SYSTEM =======");
        System.out.println();
        System.out.println("Payload            : " + shown);
        System.out.println("Payload length     : " + payload.length());
        System.out.println();
        System.out.println("Payload scanned successfully.");

        for (Match m : result.sortedMatches()) {
            System.out.println();
            System.out.println("Matching Signature : " + m.getSignature());
            System.out.println("Matched Text       : " + payload.substring(m.getStart(), m.getEnd() + 1));
            System.out.println("Starting Position  : " + m.getStart() + "  (0-based)");
            System.out.println("Ending Position    : " + m.getEnd());
            System.out.println("Detection Status   : SIGNATURE DETECTED");
        }

        System.out.println();
        System.out.println("------------------------------------------");
        System.out.println("Total matches      : " + result.matchCount());
        System.out.println(String.format("Scan time          : %.3f ms", result.getScanNanos() / 1e6));
        System.out.println("Automaton          : " + automaton.signatureCount() + " signatures, "
                + automaton.stateCount() + " states");
        if (result.isDetected()) {
            System.out.println("Result             : SIGNATURE(S) DETECTED - review recommended");
            System.out.println("Note               : a match does not prove an attack; it flags text for investigation.");
        } else {
            System.out.println("Result             : NO MATCH FOUND");
        }
    }
}
