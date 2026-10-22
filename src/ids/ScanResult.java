package ids;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Outcome of scanning one payload. */
public final class ScanResult {

    private final String payload;
    private final List<Match> matches; // in the order the automaton found them (by end position)
    private final long scanNanos;

    public ScanResult(String payload, List<Match> matches, long scanNanos) {
        this.payload = payload;
        this.matches = matches;
        this.scanNanos = scanNanos;
    }

    public String getPayload() {
        return payload;
    }

    public boolean isDetected() {
        return !matches.isEmpty();
    }

    public int matchCount() {
        return matches.size();
    }

    public long getScanNanos() {
        return scanNanos;
    }

    /** Copy sorted by position, for display (sorting is not part of the O(M+Z) scan). */
    public List<Match> sortedMatches() {
        List<Match> copy = new ArrayList<Match>(matches);
        Collections.sort(copy, Match.BY_POSITION);
        return copy;
    }
}
