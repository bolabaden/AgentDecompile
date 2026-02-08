/* ###
 * IP: AgentDecompile
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package agentdecompile.debug;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import ghidra.framework.Application;
import agentdecompile.util.AgentDecompileToolLogger;

/**
 * Service for capturing debug information and creating a zip file.
 * <p>
 * Ghidra API: {@link ghidra.framework.Application} -
 * <a href="https://ghidra.re/ghidra_docs/api/ghidra/framework/Application.html">Application API</a>.
 * Uses {@link agentdecompile.debug.DebugInfoCollector} for data collection.
 * </p>
 */
public class DebugCaptureService {

    private static final int MAX_LOG_LINES = 5000;
    private static final DateTimeFormatter TIMESTAMP_FORMAT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH-mm-ss");
    private static final ObjectMapper JSON = new ObjectMapper()
        .enable(SerializationFeature.INDENT_OUTPUT);

    private final DebugInfoCollector collector;

    public DebugCaptureService() {
        this.collector = new DebugInfoCollector();
    }

    /**
     * Capture debug information and create a zip file.
     * @param userMessage Optional user-provided message describing the issue
     * @return The created zip file
     * @throws IOException If an error occurs creating the zip file
     */
    public File captureDebugInfo(String userMessage) throws IOException {
        // Create output file in Ghidra user settings directory
        File debugDir = getDebugDirectory();

        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMAT);
        String dirName = String.format("agentdecompile-debug-%s", timestamp);
        String filename = dirName + ".zip";
        File outputFile = new File(debugDir, filename);

        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(outputFile))) {
            // Collect and write debug info JSON
            Map<String, Object> debugInfo = collector.collectAll(userMessage);
            writeJsonEntry(zos, dirName + "/debug-info.json", debugInfo);

            // Write log file (truncated)
            String logContent = getLogFileContent(MAX_LOG_LINES);
            writeTextEntry(zos, dirName + "/application.log.txt", logContent);

            // Write AgentDecompile tool request/response log if it exists
            String agentdecompileToolsLogContent = getAgentDecompileToolsLogContent(MAX_LOG_LINES);
            if (agentdecompileToolsLogContent != null) {
                writeTextEntry(zos, dirName + "/agentdecompile-tools.log.txt", agentdecompileToolsLogContent);
            }

            // Write README
            writeTextEntry(zos, dirName + "/README.txt", createReadme(debugInfo));
        }

        return outputFile;
    }

    /**
     * Read the Ghidra application log file content.
     * @param maxLines Maximum number of lines to read from the end
     * @return Log content as a string
     */
    private String getLogFileContent(int maxLines) {
        try {
            File userSettingsDir = Application.getUserSettingsDirectory();
            File logFile = new File(userSettingsDir, "application.log");

            if (!logFile.exists()) {
                return "Log file not found: " + logFile.getPath();
            }

            List<String> allLines = Files.readAllLines(logFile.toPath());
            int startIndex = Math.max(0, allLines.size() - maxLines);
            List<String> tailLines = allLines.subList(startIndex, allLines.size());

            StringBuilder sb = new StringBuilder();
            sb.append("=== Last ").append(tailLines.size()).append(" lines of application.log ===\n\n");
            for (String line : tailLines) {
                sb.append(line).append("\n");
            }
            return sb.toString();
        } catch (Exception e) {
            return "Error reading log file: " + e.getMessage();
        }
    }

    /**
     * Read the AgentDecompile tool request/response log file content.
     * @param maxLines Maximum number of lines to read from the end
     * @return Log content as a string, or null if file doesn't exist
     */
    private String getAgentDecompileToolsLogContent(int maxLines) {
        try {
            File logFile = AgentDecompileToolLogger.getLogFile();
            if (logFile == null || !logFile.exists()) {
                return null; // Log file doesn't exist - logging may not be enabled
            }

            List<String> allLines = Files.readAllLines(logFile.toPath());
            if (allLines.isEmpty()) {
                return null; // Empty log file
            }

            int startIndex = Math.max(0, allLines.size() - maxLines);
            List<String> tailLines = allLines.subList(startIndex, allLines.size());

            StringBuilder sb = new StringBuilder();
            sb.append("=== Last ").append(tailLines.size()).append(" lines of agentdecompile-tools.log ===\n\n");
            for (String line : tailLines) {
                sb.append(line).append("\n");
            }
            return sb.toString();
        } catch (Exception e) {
            return "Error reading AgentDecompile tools log file: " + e.getMessage();
        }
    }

    /**
     * Get the directory for storing debug captures.
     * Creates the directory if it doesn't exist.
     * @return The debug directory ({ghidra_user_settings}/agentdecompile/debug/)
     */
    private File getDebugDirectory() {
        File userSettingsDir = Application.getUserSettingsDirectory();
        File agentdecompileDir = new File(userSettingsDir, "agentdecompile");
        File debugDir = new File(agentdecompileDir, "debug");

        if (!debugDir.exists()) {
            debugDir.mkdirs();
        }

        return debugDir;
    }

    /**
     * Write a JSON entry to the zip file.
     */
    private void writeJsonEntry(ZipOutputStream zos, String name, Object data) throws IOException {
        ZipEntry entry = new ZipEntry(name);
        zos.putNextEntry(entry);
        String json = JSON.writeValueAsString(data);
        zos.write(json.getBytes(StandardCharsets.UTF_8));
        zos.closeEntry();
    }

    /**
     * Write a text entry to the zip file.
     */
    private void writeTextEntry(ZipOutputStream zos, String name, String content) throws IOException {
        ZipEntry entry = new ZipEntry(name);
        zos.putNextEntry(entry);
        zos.write(content.getBytes(StandardCharsets.UTF_8));
        zos.closeEntry();
    }

    /**
     * Create a README file for the debug archive.
     */
    private String createReadme(Map<String, Object> debugInfo) {
        StringBuilder sb = new StringBuilder();
        sb.append("AgentDecompile Debug Capture\n");
        sb.append("==================\n\n");
        sb.append("This archive contains debug information for troubleshooting AgentDecompile issues.\n\n");
        sb.append("Contents:\n");
        sb.append("- debug-info.json: System, Ghidra, and AgentDecompile configuration\n");
        sb.append("- application.log.txt: Last ").append(MAX_LOG_LINES).append(" lines of Ghidra application log\n");
        sb.append("- agentdecompile-tools.log.txt: MCP tool request/response log (if Request Logging is enabled)\n\n");
        sb.append("Captured: ").append(debugInfo.get("captureTimestamp")).append("\n\n");
        sb.append("User Message:\n");
        sb.append(debugInfo.get("userMessage")).append("\n");
        return sb.toString();
    }
}
