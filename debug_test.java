import ghidra.framework.options.ToolOptions;
import agentdecompile.plugin.ConfigManager;
import ghidra.framework.plugintool.PluginTool;

public class debug_test {
    public static void main(String[] args) {
        // This is a simplified version to debug
        System.out.println("AGENT_DECOMPILE_API_KEY env: '" + System.getenv("AGENT_DECOMPILE_API_KEY") + "'");

        // Simulate what the test does
        PluginTool tool = null; // We can't easily create this outside Ghidra
        if (tool != null) {
            ToolOptions options = tool.getOptions(ConfigManager.SERVER_OPTIONS);
            options.removeOption(ConfigManager.API_KEY);
            ConfigManager configManager = new ConfigManager(tool);
            String apiKey = configManager.getApiKey();
            System.out.println("API key from ConfigManager: '" + apiKey + "'");
            String[] parts = apiKey.split("-", 2);
            System.out.println("Parts length: " + parts.length);
            System.out.println("Part 0: '" + parts[0] + "'");
        } else {
            System.out.println("Cannot test without PluginTool");
        }
    }
}