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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.modelcontextprotocol.spec.McpSchema;

/**
 * Utility methods for creating MCP JSON schemas.
 * <p>
 * MCP SDK references:
 * <ul>
 *   <li>{@link io.modelcontextprotocol.spec.McpSchema.JsonSchema} - MCP schema for tool parameters</li>
 *   <li>MCP Java SDK: <a href="https://github.com/modelcontextprotocol/java-sdk">MCP Java SDK</a></li>
 *   <li>MCP Server docs: <a href="https://modelcontextprotocol.info/docs/sdk/java/mcp-server/">MCP Java Server</a></li>
 * </ul>
 * </p>
 */
public class SchemaUtil {
    /**
     * Create a string property schema
     * @param description Description of the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> stringProperty(String description) {
        return Map.of(
            "type", "string",
            "description", description
        );
    }

    /**
     * Create a string property schema (alias for consistency)
     * @param description Description of the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> createStringProperty(String description) {
        return stringProperty(description);
    }

    /**
     * Create a string property schema with a default value
     * @param description Description of the property
     * @param defaultValue Default value for the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> stringPropertyWithDefault(String description, String defaultValue) {
        return Map.of(
            "type", "string",
            "description", description,
            "default", defaultValue
        );
    }

    /**
     * Create an optional string property schema (alias)
     * @param description Description of the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> createOptionalStringProperty(String description) {
        return stringProperty(description);
    }

    /**
     * Create a boolean property schema
     * @param description Description of the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> booleanProperty(String description) {
        return Map.of(
            "type", "boolean",
            "description", description
        );
    }

    /**
     * Create an optional boolean property schema (alias)
     * @param description Description of the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> createOptionalBooleanProperty(String description) {
        return booleanProperty(description);
    }

    /**
     * Create a boolean property schema with a default value
     * @param description Description of the property
     * @param defaultValue Default value for the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> booleanPropertyWithDefault(String description, boolean defaultValue) {
        return Map.of(
            "type", "boolean",
            "description", description,
            "default", defaultValue
        );
    }

    /**
     * Create an integer property schema
     * @param description Description of the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> integerProperty(String description) {
        return Map.of(
            "type", "integer",
            "description", description
        );
    }

    /**
     * Create a number property schema
     * @param description Description of the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> createNumberProperty(String description) {
        return integerProperty(description);
    }

    /**
     * Create an optional number property schema
     * @param description Description of the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> createOptionalNumberProperty(String description) {
        return integerProperty(description);
    }

    /**
     * Create an integer property schema with a default value
     * @param description Description of the property
     * @param defaultValue Default value for the property
     * @return Map representation of the property schema
     */
    public static Map<String, Object> integerPropertyWithDefault(String description, int defaultValue) {
        return Map.of(
            "type", "integer",
            "description", description,
            "default", defaultValue
        );
    }

    /**
     * Create an object property schema
     * @param description Description of the property
     * @param properties Properties of the object
     * @return Map representation of the property schema
     */
    public static Map<String, Object> createOptionalObjectProperty(String description, Map<String, Object> properties) {
        Map<String, Object> schema = new HashMap<>();
        schema.put("type", "object");
        schema.put("description", description);
        schema.put("properties", properties);
        return schema;
    }

    /**
     * Create a JSON schema object
     * @param properties Map of property names to property schemas
     * @param required List of required property names
     * @return JsonSchema object
     */
    public static McpSchema.JsonSchema createSchema(Map<String, Object> properties, List<String> required) {
        // Allow additional properties to be ignored rather than causing validation errors
        return new McpSchema.JsonSchema("object", properties, required, true, null, null);
    }

    /**
     * Create a schema builder to fluently build a schema
     * @return A new schema builder
     */
    public static SchemaBuilder builder() {
        return new SchemaBuilder();
    }

    /**
     * Builder class for creating schemas
     */
    public static class SchemaBuilder {
        private final Map<String, Object> properties = new HashMap<>();
        private final List<String> required = new java.util.ArrayList<>();

        private SchemaBuilder() {
            // Private constructor to force use of SchemaUtil.builder()
        }

        /**
         * Add a string property
         * @param name Property name
         * @param description Property description
         * @return This builder for method chaining
         */
        public SchemaBuilder stringProperty(String name, String description) {
            properties.put(name, SchemaUtil.stringProperty(description));
            return this;
        }

        /**
         * Add a string property with a default value
         * @param name Property name
         * @param description Property description
         * @param defaultValue Default value
         * @return This builder for method chaining
         */
        public SchemaBuilder stringProperty(String name, String description, String defaultValue) {
            properties.put(name, SchemaUtil.stringPropertyWithDefault(description, defaultValue));
            return this;
        }

        /**
         * Add a boolean property
         * @param name Property name
         * @param description Property description
         * @return This builder for method chaining
         */
        public SchemaBuilder booleanProperty(String name, String description) {
            properties.put(name, SchemaUtil.booleanProperty(description));
            return this;
        }

        /**
         * Add a boolean property with a default value
         * @param name Property name
         * @param description Property description
         * @param defaultValue Default value
         * @return This builder for method chaining
         */
        public SchemaBuilder booleanProperty(String name, String description, boolean defaultValue) {
            properties.put(name, SchemaUtil.booleanPropertyWithDefault(description, defaultValue));
            return this;
        }

        /**
         * Add an integer property
         * @param name Property name
         * @param description Property description
         * @return This builder for method chaining
         */
        public SchemaBuilder integerProperty(String name, String description) {
            properties.put(name, SchemaUtil.integerProperty(description));
            return this;
        }

        /**
         * Add an integer property with a default value
         * @param name Property name
         * @param description Property description
         * @param defaultValue Default value
         * @return This builder for method chaining
         */
        public SchemaBuilder integerProperty(String name, String description, int defaultValue) {
            properties.put(name, SchemaUtil.integerPropertyWithDefault(description, defaultValue));
            return this;
        }

        /**
         * Add a required property
         * @param name Property name
         * @return This builder for method chaining
         */
        public SchemaBuilder required(String name) {
            required.add(name);
            return this;
        }

        /**
         * Build the schema
         * @return JsonSchema object
         */
        public McpSchema.JsonSchema build() {
            return SchemaUtil.createSchema(properties, required);
        }
    }
}
