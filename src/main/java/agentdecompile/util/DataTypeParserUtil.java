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
package agentdecompile.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.services.DataTypeArchiveService;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import agentdecompile.plugin.AgentDecompileProgramManager;

/**
 * Utility class for parsing data types from strings.
 * Used by various tools that need to convert string representations to Ghidra data types.
 * <p>
 * Ghidra Data Type API references:
 * <ul>
 *   <li>{@link ghidra.program.model.data.DataTypeManager} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataTypeManager.html">DataTypeManager API</a></li>
 *   <li>{@link ghidra.program.model.data.DataType} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataType.html">DataType API</a></li>
 *   <li>{@link ghidra.util.data.DataTypeParser} - <a href="https://ghidra.re/ghidra_docs/api/ghidra/util/data/DataTypeParser.html">DataTypeParser API</a></li>
 * </ul>
 * See <a href="https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/package-summary.html">ghidra.program.model.data package</a>.
 * </p>
 */
public class DataTypeParserUtil {

    /**
     * Find a data type manager by name
     * @param name Name of the data type manager
     * @return The data type manager or null if not found
     */
    public static DataTypeManager findDataTypeManager(String name) {
        return findDataTypeManager(name, null);
    }

    /**
     * Find a data type manager by name, prioritizing the specified program
     * @param name Name of the data type manager
     * @param programPath Path to the program to prioritize (can be null)
     * @return The data type manager or null if not found
     */
    public static DataTypeManager findDataTypeManager(String name, String programPath) {
        // First check the specified program (highest priority)
        if (programPath != null && !programPath.isEmpty()) {
            Program targetProgram = AgentDecompileProgramManager.getProgramByPath(programPath);
            if (targetProgram != null) {
                // Ghidra API: Program.getDataTypeManager() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getDataTypeManager()
                DataTypeManager dtm = targetProgram.getDataTypeManager();
                // Ghidra API: DataTypeManager.getName() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataTypeManager.html#getName()
                if (dtm.getName().equals(name)) {
                    return dtm;
                }
            }
        }

        // Then check all open programs (program-specific data types)
        List<Program> openPrograms = AgentDecompileProgramManager.getOpenPrograms();
        for (Program program : openPrograms) {
            // Ghidra API: Program.getDataTypeManager() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getDataTypeManager()
            DataTypeManager dtm = program.getDataTypeManager();
            // Ghidra API: DataTypeManager.getName() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataTypeManager.html#getName()
            if (dtm.getName().equals(name)) {
                return dtm;
            }
        }

        // Then check standalone data type managers (loaded/associated archives)
        agentdecompile.plugin.AgentDecompilePlugin plugin = AgentDecompileInternalServiceRegistry.getService(agentdecompile.plugin.AgentDecompilePlugin.class);
        if (plugin != null) {
            // Ghidra API: PluginTool.getService(Class) - https://ghidra.re/ghidra_docs/api/ghidra/framework/plugintool/PluginTool.html#getService(java.lang.Class)
            DataTypeArchiveService archiveService = plugin.getTool().getService(DataTypeArchiveService.class);
            if (archiveService != null) {
                // Ghidra API: DataTypeArchiveService.getDataTypeManagers() - https://ghidra.re/ghidra_docs/api/ghidra/app/services/DataTypeArchiveService.html#getDataTypeManagers()
                DataTypeManager[] managers = archiveService.getDataTypeManagers();
                for (DataTypeManager dtm : managers) {
                    // Ghidra API: DataTypeManager.getName() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataTypeManager.html#getName()
                    if (dtm.getName().equals(name)) {
                        return dtm;
                    }
                }
            }
        }

        // Ghidra API: BuiltInDataTypeManager.getDataTypeManager() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/BuiltInDataTypeManager.html#getDataTypeManager()
        DataTypeManager builtInDTM = BuiltInDataTypeManager.getDataTypeManager();
        // Ghidra API: DataTypeManager.getName() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataTypeManager.html#getName()
        if (builtInDTM.getName().equals(name)) {
            return builtInDTM;
        }

        return null;
    }

    /**
     * Parse a data type from its string representation and return the actual DataType object
     * This method is for internal use by tools that need the actual DataType object,
     * not for MCP responses which should only contain metadata.
     *
     * @param dataTypeString String representation of the data type (e.g., "char**", "int[10]")
     * @param archiveName Optional name of specific archive to search in, or empty string to search all
     * @return The DataType object or null if not found
     * @throws Exception if there's an error parsing the data type
     */
    public static DataType parseDataTypeObjectFromString(String dataTypeString, String archiveName)
            throws Exception {
        if (dataTypeString == null || dataTypeString.isEmpty()) {
            throw new IllegalArgumentException("No data type string provided");
        }

        // Get data type managers to search in - for this method we use empty programPath since it's the legacy method
        List<DataTypeManager> managersToSearch = getDataTypeManagersToSearch(archiveName, "");
        if (managersToSearch.isEmpty()) {
            throw new IllegalStateException("No data type managers available");
        }

        // Search for the data type
        for (DataTypeManager dtm : managersToSearch) {
            try {
                // Ghidra API: DataTypeParser.<init>(DataTypeManager, DataTypeManager, DataTypeManager, AllowedDataTypes) - https://ghidra.re/ghidra_docs/api/ghidra/util/data/DataTypeParser.html
                ghidra.util.data.DataTypeParser parser = new ghidra.util.data.DataTypeParser(
                    dtm, dtm, null, ghidra.util.data.DataTypeParser.AllowedDataTypes.ALL);

                // Ghidra API: DataTypeParser.parse(String) - https://ghidra.re/ghidra_docs/api/ghidra/util/data/DataTypeParser.html#parse(java.lang.String)
                DataType dt = parser.parse(dataTypeString);
                if (dt != null) {
                    return dt;
                }
            } catch (Exception e) {
                // Continue with next manager if this one fails
            }
        }

        return null;
    }


    /**
     * Parse a data type from its string representation with program context
     * @param dataTypeString String representation of the data type (e.g., "char**", "int[10]")
     * @param archiveName Optional name of specific archive to search in, or empty string to search all
     * @param programPath Path to the program to prioritize for searching
     * @return Map containing the found data type information or null if not found
     * @throws Exception if there's an error parsing the data type
     */
    public static Map<String, Object> parseDataTypeFromString(String dataTypeString, String archiveName, String programPath)
            throws Exception {
        if (dataTypeString == null || dataTypeString.isEmpty()) {
            throw new IllegalArgumentException("No data type string provided");
        }

        // Get data type managers to search in
        List<DataTypeManager> managersToSearch = getDataTypeManagersToSearch(archiveName, programPath);
        if (managersToSearch.isEmpty()) {
            throw new IllegalStateException("No data type managers available");
        }

        // Search for the data type
        DataType foundDataType = null;
        DataTypeManager foundManager = null;

        for (DataTypeManager dtm : managersToSearch) {
            try {
                // Ghidra API: DataTypeParser.<init>(DataTypeManager, DataTypeManager, DataTypeManager, AllowedDataTypes) - https://ghidra.re/ghidra_docs/api/ghidra/util/data/DataTypeParser.html
                ghidra.util.data.DataTypeParser parser = new ghidra.util.data.DataTypeParser(
                    dtm, dtm, null, ghidra.util.data.DataTypeParser.AllowedDataTypes.ALL);

                // Ghidra API: DataTypeParser.parse(String) - https://ghidra.re/ghidra_docs/api/ghidra/util/data/DataTypeParser.html#parse(java.lang.String)
                DataType dt = parser.parse(dataTypeString);
                if (dt != null) {
                    foundDataType = dt;
                    foundManager = dtm;
                    break;
                }
            } catch (Exception e) {
                // Continue with next manager if this one fails
            }
        }

        if (foundDataType == null) {
            return null;
        }

        // Create result data
        // NOTE: We do NOT include the actual DataType object in the response map
        // as it can contain circular references and recursive structures that would
        // cause serialization issues. Instead, we only include metadata about the data type.
        Map<String, Object> dataTypeInfo = createDataTypeInfo(foundDataType);
        // Ghidra API: DataTypeManager.getName() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataTypeManager.html#getName()
        dataTypeInfo.put("archiveName", foundManager.getName());
        dataTypeInfo.put("requestedString", dataTypeString);

        return dataTypeInfo;
    }


    /**
     * Get list of data type managers to search based on the archive name and program context
     * @param archiveName Name of archive to search in, or empty string to search all
     * @param programPath Path to the program to search in (required)
     * @return List of data type managers to search
     */
    private static List<DataTypeManager> getDataTypeManagersToSearch(String archiveName, String programPath) {
        List<DataTypeManager> managersToSearch = new ArrayList<>();

        if (archiveName != null && !archiveName.isEmpty()) {
            // Search in the specified archive only, prioritizing the specified program
            DataTypeManager dtm = findDataTypeManager(archiveName, programPath);
            if (dtm != null) {
                managersToSearch.add(dtm);
            }
            // If looking for a specific archive but not found, still include built-in types as fallback
            if (managersToSearch.isEmpty()) {
                // Ghidra API: BuiltInDataTypeManager.getDataTypeManager() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/BuiltInDataTypeManager.html#getDataTypeManager()
                managersToSearch.add(BuiltInDataTypeManager.getDataTypeManager());
            }
        } else {
            // Ghidra API: BuiltInDataTypeManager.getDataTypeManager() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/BuiltInDataTypeManager.html#getDataTypeManager()
            managersToSearch.add(BuiltInDataTypeManager.getDataTypeManager());

            // Add the specified program's data type manager first
            Program targetProgram = AgentDecompileProgramManager.getProgramByPath(programPath);
            if (targetProgram != null) {
                // Ghidra API: Program.getDataTypeManager() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getDataTypeManager()
                managersToSearch.add(targetProgram.getDataTypeManager());
            }

            // Add other open program data type managers
            List<Program> openPrograms = AgentDecompileProgramManager.getOpenPrograms();
            for (Program program : openPrograms) {
                // Ghidra API: Program.getDomainFile(), DomainFile.getPathname() - https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainObject.html#getDomainFile(), https://ghidra.re/ghidra_docs/api/ghidra/framework/model/DomainFile.html#getPathname()
                if (targetProgram != null && program.getDomainFile().getPathname().equals(targetProgram.getDomainFile().getPathname())) {
                    continue;
                }
                // Ghidra API: Program.getDataTypeManager() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html#getDataTypeManager()
                managersToSearch.add(program.getDataTypeManager());
            }

            agentdecompile.plugin.AgentDecompilePlugin plugin = AgentDecompileInternalServiceRegistry.getService(agentdecompile.plugin.AgentDecompilePlugin.class);
            if (plugin != null) {
                // Ghidra API: PluginTool.getService(Class) - https://ghidra.re/ghidra_docs/api/ghidra/framework/plugintool/PluginTool.html#getService(java.lang.Class)
                DataTypeArchiveService archiveService = plugin.getTool().getService(DataTypeArchiveService.class);
                if (archiveService != null) {
                    // Ghidra API: DataTypeArchiveService.getDataTypeManagers() - https://ghidra.re/ghidra_docs/api/ghidra/app/services/DataTypeArchiveService.html#getDataTypeManagers()
                    Collections.addAll(managersToSearch, archiveService.getDataTypeManagers());
                }
            }
        }

        return managersToSearch;
    }

    /**
     * Create a map with information about a data type
     * @param dt The data type
     * @return Map with data type information
     */
    public static Map<String, Object> createDataTypeInfo(DataType dt) {
        Map<String, Object> info = new HashMap<>();
        // Ghidra API: DataType.getName() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataType.html#getName()
        info.put("name", dt.getName());
        // Ghidra API: DataType.getDisplayName() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataType.html#getDisplayName()
        info.put("displayName", dt.getDisplayName());
        // Ghidra API: DataType.getCategoryPath(), CategoryPath.getPath() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataType.html#getCategoryPath()
        info.put("categoryPath", dt.getCategoryPath().getPath());
        // Ghidra API: DataType.getDescription() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataType.html#getDescription()
        info.put("description", dt.getDescription());
        // Ghidra API: DataType.getUniversalID(), UniversalID.getValue() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataType.html#getUniversalID()
        info.put("id", dt.getUniversalID() != null ? dt.getUniversalID().getValue() : null);
        // Ghidra API: DataType.getLength() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataType.html#getLength()
        info.put("size", dt.getLength());
        // Ghidra API: DataType.getAlignment() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataType.html#getAlignment()
        info.put("alignment", dt.getAlignment());
        info.put("dataTypeName", dt.getClass().getSimpleName());

        // Ghidra API: DataType.getDataTypeManager(), getSourceArchive(), SourceArchive.getName() - https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataType.html#getSourceArchive()
        if (dt.getDataTypeManager() != null) {
            info.put("sourceArchiveName", dt.getSourceArchive() != null ?
                dt.getSourceArchive().getName() : "Local");
        }

        return info;
    }
}
