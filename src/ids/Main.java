package ids;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Scanner;

public final class Main {

    private static Path signatureFile;

    private static final String[] DEFAULT_SIGNATURES = {
        "UNION SELECT",
        "DROP TABLE",
        "../etc/passwd",
        "cmd.exe",
        "<script>",
        "' OR '1'='1"
    };

    private static final String[] SAMPLE_PAYLOADS = {
        "Request: UNION SELECT username FROM users",
        "Request: UNION SELECT data; DROP TABLE users",
        "GET /download?file=../../etc/passwd HTTP/1.1",
        "POST /login user=admin&comment=<script>alert(1)</script>",
        "GET /index.html HTTP/1.1 Host: example.com"
    };

    private static final String CSV_FILE = "benchmark_results.csv";

    public static void main(String[] args) {

        signatureFile = locateSignatureFile();

        System.out.println("Working directory: "
                + Paths.get("").toAbsolutePath().normalize());

        System.out.println("Signature file: "
                + signatureFile.toAbsolutePath().normalize());

        AhoCorasick automaton = new AhoCorasick();

        loadSignatures(automaton);

        PayloadScanner scanner = new PayloadScanner(automaton);

        if (args.length > 0 && args[0].equalsIgnoreCase("demo")) {
            runSamples(scanner, automaton);
            return;
        }

        if (args.length > 0
                && args[0].equalsIgnoreCase("benchmark")) {
            Benchmark.run(System.out, CSV_FILE);
            return;
        }

        interactive(automaton, scanner);
    }

    // ---------------------------------------------------------
    // LOCATE SIGNATURE FILE
    // ---------------------------------------------------------

    private static Path locateSignatureFile() {

        Path current = Paths.get("").toAbsolutePath().normalize();
        Path directory = current;

        while (directory != null) {

            Path candidate = directory.resolve("data")
                    .resolve("signatures.txt");

            if (Files.isRegularFile(candidate)) {
                return candidate;
            }

            directory = directory.getParent();
        }

        return current.resolve("data").resolve("signatures.txt");
    }

    // ---------------------------------------------------------
    // LOAD SIGNATURES
    // ---------------------------------------------------------

    private static void loadSignatures(AhoCorasick automaton) {

        try {
            Path parent = signatureFile.getParent();

            if (parent != null) {
                Files.createDirectories(parent);
            }

            if (!Files.exists(signatureFile)) {

                for (String signature : DEFAULT_SIGNATURES) {
                    automaton.addSignature(signature);
                }

                if (saveSignatures(automaton)) {
                    System.out.println("Created signature file.");
                }

                return;
            }

            int count = 0;

            try (BufferedReader reader = Files.newBufferedReader(
                    signatureFile, StandardCharsets.UTF_8)) {

                String line;

                while ((line = reader.readLine()) != null) {

                    String signature = line.trim();

                    if (signature.isEmpty()) {
                        continue;
                    }

                    try {
                        if (automaton.addSignature(signature)) {
                            count++;
                        }
                    } catch (IllegalArgumentException e) {
                        System.out.println(
                                "Invalid signature skipped: " + signature);
                    }
                }
            }

            System.out.println("Loaded signatures: " + count);

        } catch (IOException e) {
            System.out.println("ERROR loading signatures: "
                    + e.getMessage());
        }
    }

    // ---------------------------------------------------------
    // SAVE SIGNATURES
    // ---------------------------------------------------------

    private static boolean saveSignatures(AhoCorasick automaton) {

        try {
            Path parent = signatureFile.getParent();

            if (parent != null) {
                Files.createDirectories(parent);
            }

            try (BufferedWriter writer = Files.newBufferedWriter(
                    signatureFile, StandardCharsets.UTF_8)) {

                for (String signature : automaton.getSignatures()) {
                    writer.write(signature);
                    writer.newLine();
                }
            }

            System.out.println("SUCCESS: Signatures saved.");
            System.out.println("Saved file: "
                    + signatureFile.toAbsolutePath().normalize());

            return true;

        } catch (IOException e) {
            System.out.println("ERROR saving signatures: "
                    + e.getMessage());

            return false;
        }
    }

    // ---------------------------------------------------------
    // MENU
    // ---------------------------------------------------------

    private static void interactive(
            AhoCorasick automaton,
            PayloadScanner scanner) {

        Scanner in = new Scanner(System.in);

        while (true) {

            System.out.println();
            System.out.println("======= INTRUSION DETECTION SYSTEM =======");
            System.out.println(" 1. Scan a payload");
            System.out.println(" 2. Add a signature");
            System.out.println(" 3. Remove a signature");
            System.out.println(" 4. List signatures");
            System.out.println(" 5. Scan a text file");
            System.out.println(" 6. Run sample payloads");
            System.out.println(" 7. Run benchmark");
            System.out.println(" 8. Run DatasetRunner (automated tests)");
            System.out.println(" 0. Exit");
            System.out.print("Choice: ");

            if (!in.hasNextLine()) {
                return;
            }

            String choice = in.nextLine().trim();

            switch (choice) {

                case "0":
                    System.out.println("Goodbye.");
                    return;

                case "1":
                    System.out.print("Enter payload: ");

                    if (in.hasNextLine()) {
                        report(scanner.scan(in.nextLine()), automaton);
                    }
                    break;

                case "2":
                    System.out.print("Enter new signature: ");

                    if (in.hasNextLine()) {
                        addSignature(automaton, in.nextLine().trim());
                    }
                    break;

                case "3":
                    System.out.print("Enter signature to remove: ");

                    if (in.hasNextLine()) {
                        removeSignature(
                                automaton, in.nextLine().trim());
                    }
                    break;

                case "4":
                    listSignatures(automaton);
                    break;

                case "5":
                    System.out.print("Enter payload file path: ");

                    if (in.hasNextLine()) {
                        scanFile(in.nextLine().trim(), scanner, automaton);
                    }
                    break;

                case "6":
                    runSamples(scanner, automaton);
                    break;

                case "7":
                    Benchmark.run(System.out, CSV_FILE);
                    break;

                case "8":
                    DatasetRunner.run(automaton, false);
                    break;

                default:
                    System.out.println("Invalid choice.");
            }
        }
    }

    // ---------------------------------------------------------
    // ADD SIGNATURE
    // ---------------------------------------------------------

    private static void addSignature(
            AhoCorasick automaton, String signature) {

        if (signature.isEmpty()) {
            System.out.println("Signature cannot be empty.");
            return;
        }

        try {
            if (automaton.addSignature(signature)) {

                if (saveSignatures(automaton)) {
                    System.out.println(
                            "Signature added permanently: " + signature);
                } else {
                    automaton.removeSignature(signature);
                    System.out.println(
                            "Save failed. Addition was cancelled.");
                }

            } else {
                System.out.println(
                        "Signature already exists (case-insensitive).");
            }

        } catch (IllegalArgumentException e) {
            System.out.println("Rejected: " + e.getMessage());
        }
    }

    // ---------------------------------------------------------
    // REMOVE SIGNATURE
    // ---------------------------------------------------------

    private static void removeSignature(
            AhoCorasick automaton, String signature) {

        if (!automaton.removeSignature(signature)) {
            System.out.println("Signature not found.");
            return;
        }

        if (saveSignatures(automaton)) {
            System.out.println(
                    "Signature removed permanently: " + signature);
        } else {
            System.out.println(
                    "WARNING: Could not update the text file.");
        }
    }

    // ---------------------------------------------------------
    // LIST SIGNATURES
    // ---------------------------------------------------------

    private static void listSignatures(AhoCorasick automaton) {

        List<String> signatures = automaton.getSignatures();

        System.out.println();
        System.out.println("Signatures (" + signatures.size() + "):");

        for (int i = 0; i < signatures.size(); i++) {
            System.out.println((i + 1) + ". " + signatures.get(i));
        }

        System.out.println("File: "
                + signatureFile.toAbsolutePath().normalize());
    }

    // ---------------------------------------------------------
    // SCAN SAMPLE PAYLOADS
    // ---------------------------------------------------------

    private static void runSamples(
            PayloadScanner scanner,
            AhoCorasick automaton) {

        for (String payload : SAMPLE_PAYLOADS) {
            report(scanner.scan(payload), automaton);
        }
    }

    // ---------------------------------------------------------
    // SCAN A TEXT FILE
    // ---------------------------------------------------------

    private static void scanFile(
            String path,
            PayloadScanner scanner,
            AhoCorasick automaton) {

        int lineNumber = 0;
        int flagged = 0;

        try (BufferedReader reader = Files.newBufferedReader(
                Paths.get(path), StandardCharsets.UTF_8)) {

            String line;

            while ((line = reader.readLine()) != null) {

                lineNumber++;

                ScanResult result = scanner.scan(line);

                if (result.isDetected()) {
                    flagged++;

                    System.out.println("Line " + lineNumber
                            + ": " + result.matchCount() + " match(es)");

                    report(result, automaton);
                }
            }

            System.out.println("Scanned " + lineNumber
                    + " lines; " + flagged + " flagged.");

        } catch (IOException e) {
            System.out.println("Could not read file: "
                    + e.getMessage());
        }
    }

    // ---------------------------------------------------------
    // DISPLAY SCAN RESULT
    // ---------------------------------------------------------

    private static void report(
            ScanResult result,
            AhoCorasick automaton) {

        String payload = result.getPayload();

        String shown = payload.length() > 80
                ? payload.substring(0, 77) + "..."
                : payload;

        System.out.println();
        System.out.println("======= INTRUSION DETECTION SYSTEM =======");
        System.out.println("Payload: " + shown);
        System.out.println("Payload length: " + payload.length());
        System.out.println("Payload scanned successfully.");

        for (Match match : result.sortedMatches()) {

            System.out.println();
            System.out.println("Matching Signature: "
                    + match.getSignature());

            System.out.println("Matched Text: "
                    + payload.substring(
                            match.getStart(), match.getEnd() + 1));

            System.out.println("Starting Position: "
                    + match.getStart() + " (0-based)");

            System.out.println("Ending Position: "
                    + match.getEnd());

            System.out.println("Detection Status: SIGNATURE DETECTED");
        }

        System.out.println("------------------------------------------");
        System.out.println("Total matches: " + result.matchCount());

        System.out.printf("Scan time: %.3f ms%n",
                result.getScanNanos() / 1e6);

        System.out.println("Automaton: "
                + automaton.signatureCount() + " signatures, "
                + automaton.stateCount() + " states");

        if (result.isDetected()) {
            System.out.println(
                    "Result: SIGNATURE(S) DETECTED - review recommended");
        } else {
            System.out.println("Result: NO MATCH FOUND");
        }
    }
}
