import java.util.UUID;

public class debug_apikey {
    public static void main(String[] args) {
        String apiKey = "AgentDecompile-" + UUID.randomUUID().toString();
        System.out.println("Generated API key: '" + apiKey + "'");
        String[] parts = apiKey.split("-", 2);
        System.out.println("Parts length: " + parts.length);
        System.out.println("Part 0: '" + parts[0] + "'");
        System.out.println("Part 1: '" + parts[1] + "'");
    }
}