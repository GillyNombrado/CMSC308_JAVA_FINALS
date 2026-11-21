package phishguard.text;

public class TextDemo {
    public static void main(String[] args) {
        String[] messages = {
            "CONGRATULATIONS!!! You won P50,000 from GCash raffle! Claim now at gcash-promo.top before it expires today!",
            "Your GCash account is locked due to unusual activity. Verify now: gcash-verify.top/login",
            "Nanalo ka ng libreng load! I-click agad ang link para ma-claim ngayon na.",
            "Hiring now! Work from home, earn daily. Send registration fee to start.",
            "Your parcel on hold due to unpaid shipping fee. Update your address here: bit.ly/3xYz",
            "Your OTP is 482913. Do not share this code with anyone. - GCash",
            "Hi, your BDO statement for October is ready. Log in at bdo.com.ph to view it.",
            "Kumusta! Meeting natin bukas ng 3pm sa library, dala ka ng laptop."
        };
        TextScamAnalyzer analyzer = new TextScamAnalyzer();
        for (String m : messages) {
            TextResult r = analyzer.analyze(m);
            System.out.printf("%s%n  Text risk: %.0f (%s)  Brands: %s%n", m, r.score, r.level(), r.brands);
            for (String reason : r.reasons) System.out.println("   - " + reason);
            System.out.println();
        }
    }
}