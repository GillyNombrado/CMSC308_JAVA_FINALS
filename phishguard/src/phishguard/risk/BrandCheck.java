package phishguard.risk;

public class BrandCheck {
    public enum Status { NONE, MATCH, MISMATCH, UNVERIFIABLE }

    public final Status status;
    public final String reason;

    public BrandCheck(Status status, String reason) {
        this.status = status;
        this.reason = reason;
    }

    public static BrandCheck none() {
        return new BrandCheck(Status.NONE, "");
    }
}