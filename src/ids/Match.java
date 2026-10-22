package ids;

import java.util.Comparator;

/** One occurrence of a signature inside a payload. Positions are 0-based and inclusive. */
public final class Match {

    /** Orders matches by start position, then end position, then signature text. */
    public static final Comparator<Match> BY_POSITION = new Comparator<Match>() {
        @Override
        public int compare(Match a, Match b) {
            if (a.start != b.start) {
                return Integer.compare(a.start, b.start);
            }
            if (a.end != b.end) {
                return Integer.compare(a.end, b.end);
            }
            return a.signature.compareTo(b.signature);
        }
    };

    private final String signature; // as configured by the user (original case)
    private final int start;
    private final int end;

    public Match(String signature, int start, int end) {
        this.signature = signature;
        this.start = start;
        this.end = end;
    }

    public String getSignature() {
        return signature;
    }

    public int getStart() {
        return start;
    }

    public int getEnd() {
        return end;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Match)) {
            return false;
        }
        Match m = (Match) o;
        return start == m.start && end == m.end && signature.equals(m.signature);
    }

    @Override
    public int hashCode() {
        return (signature.hashCode() * 31 + start) * 31 + end;
    }

    @Override
    public String toString() {
        return signature + "@" + start;
    }
}
