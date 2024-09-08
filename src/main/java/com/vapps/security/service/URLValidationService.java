package com.vapps.security.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vapps.security.config.*;
import com.vapps.security.config.RequestBodyConfig.RequestBodyType;
import com.vapps.security.exception.AppException;
import com.vapps.security.exception.NullValueException;
import jakarta.servlet.http.HttpServletRequest;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.vapps.security.util.RequestUtil.getServletPath;

@Service
public class URLValidationService {

    @Autowired(required = false)
    private WebSecurityConfiguration securityConfiguration;

    @Autowired
    private AntPathMatcher antPathMatcher;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RequestBodyValidationService requestBodyValidationService;

    private static final Logger LOGGER = LoggerFactory.getLogger(URLValidationService.class);

    public void validateURL(HttpServletRequest request) throws AppException {
        String servletPath = getServletPath(request);
        URLConfig urlConfig = getConfig(servletPath, request.getMethod()).orElseThrow(
                () -> new AppException(HttpStatus.NOT_FOUND.value(), "Oops!, URL not found!"));
        validateMandatoryParams(urlConfig, request.getParameterMap());
        validateRequestParams(urlConfig, request.getParameterMap());
        validatePathVariables(urlConfig, servletPath);
        validateRequestBody(urlConfig, request);
    }

    private void validateRequestBody(URLConfig urlConfig, HttpServletRequest request) throws AppException {
        if (urlConfig.getRequestBodyConfig() == null) {
            return;
        }
        RequestBodyType type = urlConfig.getRequestBodyConfig().getType();
        switch (type) {
            case JSON -> {
                JSONObject json = null;
                try {
                    json = parseInputStreamToJSONObject(request.getInputStream());
                } catch (IOException e) {
                    LOGGER.error(e.getMessage(), e);
                    throw new AppException(HttpStatus.BAD_REQUEST.value(), "Error while parsing JSON Object!");
                }
                validateJSONField(json, urlConfig.getRequestBodyConfig().getFields());
                validateMandatoryRequestBodyFields(urlConfig.getRequestBodyConfig().getFields(), json);
            }
            case FORM_DATA -> requestBodyValidationService.handleFormData(request, urlConfig.getRequestBodyConfig());
            default -> {
            }
        }
    }

    private void validateMandatoryRequestBodyFields(List<RequestBodyField> fields, JSONObject json)
            throws AppException {
        for (RequestBodyField field : fields) {
            if (field.isMandatory() && json.get(field.getKey()) == null) {
                throw new AppException(HttpStatus.BAD_REQUEST.value(), field.getKey() + " is mandatory!");
            }
            if (field.getType() == DataType.JSON_OBJECT) {
                validateMandatoryRequestBodyFields(field.getChildren(),
                        checkAndGetJSONObject(json.get(field.getKey())));
            }
            if (field.getType() == DataType.JSON_ARRAY_OF_OBJECT) {
                JSONArray jsonArray = checkAndGetJSONArray(json.get(field.getKey()));
                for (Object object : jsonArray) {
                    validateMandatoryRequestBodyFields(field.getChildren(), (JSONObject) object);
                }
            }
        }
    }

    private void validatePathVariables(URLConfig urlConfig, String path) throws AppException {
        Map<String, String> pathVariables = antPathMatcher.extractUriTemplateVariables(urlConfig.getPath(), path);
        for (PathVariable pathVariable : urlConfig.getPathVariables()) {
            String variableName = pathVariable.getName();
            DataType type = pathVariable.getType();
            String variableValue = pathVariables.get(variableName);

            if (variableValue == null && !pathVariable.isOptional()) {
                throw new AppException(HttpStatus.BAD_REQUEST.value(), "Missing path variable: " + variableName);
            }

            validateParamDataType(pathVariable, type, variableName, pathVariable.getRegex(), variableValue);
        }
    }

    private void validateRequestParams(URLConfig urlConfig, Map<String, String[]> params) throws AppException {
        for (Map.Entry<String, String[]> param : params.entrySet()) {
            String paramName = param.getKey();
            validateRequestParam(urlConfig, paramName, param.getValue());
        }
    }

    private void validateMandatoryParams(URLConfig urlConfig, Map<String, String[]> params) throws AppException {
        for (URLParamConfig paramConfig : urlConfig.getParams()) {
            if (paramConfig.isMandatory() && !params.containsKey(paramConfig.getName())) {
                throw new AppException(HttpStatus.BAD_REQUEST.value(),
                        "Missing mandatory parameter: " + paramConfig.getName());
            }
        }
    }

    private void validateRequestParam(URLConfig urlConfig, String paramName, String[] values) throws AppException {
        URLParamConfig paramConfig = getParamConfig(urlConfig, paramName).orElseThrow(
                () -> new AppException(HttpStatus.BAD_REQUEST.value(), "Parameter " + paramName + " is not allowed!"));
        if (paramConfig.isMultiple()) {
            for (String value : values) {
                validateParamDataType(paramConfig, paramConfig.getType(), paramConfig.getName(), paramConfig.getRegex(),
                        value);
            }
        } else {
            validateParamDataType(paramConfig, paramConfig.getType(), paramConfig.getName(), paramConfig.getRegex(),
                    values[0]);
        }

    }

    private void validateParamDataType(Field field, DataType dataType, String name, String regex, String value)
            throws AppException {
        switch (dataType) {
            case INTEGER -> {
                if (!isInteger(value)) {
                    throw new AppException(HttpStatus.BAD_REQUEST.value(),
                            "Invalid integer value for parameter: " + name);
                }
                int intValue = Integer.parseInt(value);
                if (intValue < field.getMinLength() || intValue > field.getMaxLength()) {
                    throw new AppException(HttpStatus.BAD_REQUEST.value(),
                            "Param " + name + " should be between " + field.getMinLength() + " and " + field.getMaxLength());
                }
            }
            case LONG -> {
                if (!isLong(value)) {
                    throw new AppException(HttpStatus.BAD_REQUEST.value(), "Invalid long value for parameter: " + name);
                }
                long longValue = Long.parseLong(value);
                if (longValue < field.getMinLength() || longValue > field.getMaxLength()) {
                    throw new AppException(HttpStatus.BAD_REQUEST.value(),
                            "Param " + name + " should be between " + field.getMinLength() + " and " + field.getMaxLength());
                }
            }
            case BOOLEAN -> {
                if (!isBoolean(value)) {
                    throw new AppException(HttpStatus.BAD_REQUEST.value(),
                            "Invalid boolean value for parameter: " + name);
                }
            }
            case STRING -> checkMinMax(field.getMinLength(), field.getMaxLength(), value, name);
            case REGEX -> {
                if (!Pattern.matches(regex, value)) {
                    throw new AppException(HttpStatus.BAD_REQUEST.value(),
                            "Value for parameter " + name + " does not match the required pattern.");
                }
            }
            default -> throw new AppException(HttpStatus.BAD_REQUEST.value(),
                    "Unsupported data type for parameter: " + name);
        }
    }

    private Optional<URLConfig> getConfig(String path, String method) {
        List<URLConfig> configs = securityConfiguration.getUrlConfigs().stream()
                .filter(config -> antPathMatcher.match(config.getPath(), path) && config.getMethod()
                        .matches(method.toUpperCase())).toList();
        if (configs.isEmpty()) {
            return Optional.empty();
        }
        if (configs.size() > 1) {
            /**
             *
             * If there are more configs present for same path and method it can be due to the below case
             * One path can be /api/family/{familyId} and other can be /api/family/search
             * Now for /api/family/search the /api/family/{familyId} path will also be valid according to the
             * antPathMatcher. So iterating once again the result if any path matched exactly without the antPathMatcher
             * itself then returning it.
             *
             */
            for (URLConfig urlConfig : configs) {
                if (urlConfig.getPath().equals(path)) {
                    return Optional.of(urlConfig);
                }
            }
        }
        return Optional.of(configs.get(0));
    }

    private Optional<URLParamConfig> getParamConfig(URLConfig urlConfig, String paramName) {
        return urlConfig.getParams().stream().filter(config -> config.getName().equals(paramName)).findFirst();
    }

    private boolean isInteger(Object value) {
        try {
            Integer.parseInt(String.valueOf(value));
        } catch (NumberFormatException ex) {
            return false;
        }
        return true;
    }

    private boolean isLong(Object value) {
        try {
            Long.parseLong(String.valueOf(value));
        } catch (NumberFormatException ex) {
            return false;
        }
        return true;
    }

    private boolean isBoolean(Object value) {
        return "true".equalsIgnoreCase(String.valueOf(value)) || "false".equalsIgnoreCase(String.valueOf(value));
    }

    private void validateJSONField(JSONObject json, List<RequestBodyField> fields) throws AppException {
        for (Object keyObj : json.keySet()) {
            String key = (String) keyObj;
            RequestBodyField field = fields.stream().filter(f -> f.getKey().equals(key)).findFirst().orElseThrow(
                    () -> new AppException(HttpStatus.BAD_REQUEST.value(), "Key " + key + " is not allowed!"));
            validateJSONFieldType(json, field);
        }
    }

    private void validateJSONFieldType(JSONObject json, RequestBodyField field) throws AppException {
        String key = field.getKey();
        try {
            switch (field.getType()) {
                case INTEGER ->
                        validateJSONInput(() -> checkAndGetInt(json.get(key)), "Invalid integer value for key " + key);
                case LONG ->
                        validateJSONInput(() -> checkAndGetLong(json.get(key)), "Invalid long value for key " + key);
                case BOOLEAN -> validateJSONInput(() -> checkAndGetBoolean(json.get(key)),
                        "Invalid boolean value for key" + " " + key);
                case REGEX -> validateJSONInput(() -> {
                    if (!Pattern.matches(field.getRegex(), checkAndGetString(json.get(key)))) {
                        throw new AppException(HttpStatus.BAD_REQUEST.value(),
                                "Value not matched the required pattern!");
                    }
                }, "Value for key " + key + " does not match the required pattern.");
                case JSON_OBJECT -> validateJSONInput(
                        () -> validateJSONField(checkAndGetJSONObject(json.get(key)), field.getChildren()),
                        "Invalid JSON Object for key " + key);
                case STRING -> checkMinMax(field.getMinLength(), field.getMaxLength(),
                        checkAndGetString(json.get(field.getKey())), field.getKey());
                default -> {
                }
            }
            if (isJSONArray(field)) {
                if (optJSONArray(json, key) == null) {
                    throw new AppException(HttpStatus.BAD_REQUEST.value(), "Required a JSON Array for " + key);
                }
                validateJSONArrayFieldType(checkAndGetJSONArray(json.get(key)), field);
            }
        } catch (NullValueException e) {
            if (field.isMandatory()) {
                throw new AppException(e.getStatus(), "Null value given for " + key);
            }
        }
    }

    private void validateJSONArrayFieldType(JSONArray jsonArray, RequestBodyField field) throws AppException {
        String key = field.getKey();
        try {
            switch (field.getType()) {
                case JSON_ARRAY_INT -> validateJSONInput(() -> {
                    for (int i = 0; i < jsonArray.size(); i++) {
                        checkAndGetInt(jsonArray.get(i));
                    }
                }, "Invalid JSON Array of integer for key " + key);
                case JSON_ARRAY_LONG -> validateJSONInput(() -> {
                    for (int i = 0; i < jsonArray.size(); i++) {
                        checkAndGetLong(jsonArray.get(i));
                    }
                }, "Invalid JSON Array of long for key " + key);
                case JSON_ARRAY_REGEX -> validateJSONInput(() -> {
                    for (int i = 0; i < jsonArray.size(); i++) {
                        String value = checkAndGetString(jsonArray.get(i));
                        if (!Pattern.matches(field.getRegex(), value)) {
                            throw new AppException(HttpStatus.BAD_REQUEST.value(),
                                    "Value not matched the required " + "pattern!");
                        }
                    }
                }, "Invalid JSON Array of the required pattern for key " + key);
                case JSON_ARRAY_OF_OBJECT -> validateJSONInput(() -> {
                    for (int i = 0; i < jsonArray.size(); i++) {
                        JSONObject jsonObject = checkAndGetJSONObject(jsonArray.get(i));
                        validateJSONField(jsonObject, field.getChildren());
                    }
                }, "Invalid JSON Array of objects for key " + key);
                case JSON_ARRAY_STRING -> {
                    for (int i = 0; i < jsonArray.size(); i++) {
                        checkMinMax(field.getMinLength(), field.getMaxLength(), checkAndGetString(jsonArray.get(i)),
                                field.getKey());
                    }
                }
                default -> {
                }
            }
        } catch (NullValueException e) {
            if (field.isMandatory()) {
                throw new AppException(e.getStatus(), "Null value given for " + key);
            }
        }
    }

    private JSONObject parseInputStreamToJSONObject(InputStream inputStream) throws AppException {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
            String jsonText = reader.lines().collect(Collectors.joining("\n"));
            return (JSONObject) new JSONParser().parse(jsonText);
        } catch (ParseException ex) {
            throw new AppException(HttpStatus.BAD_REQUEST.value(), "Invalid request body! Required a JSON object.");
        }
    }

    private void validateJSONInput(JSONInputValidator validator, String errorMessage) throws AppException {
        try {
            validator.validate();
        } catch (Exception ex) {
            LOGGER.error(ex.getMessage());
            throw new AppException(HttpStatus.BAD_REQUEST.value(), errorMessage);
        }
    }

    private boolean isJSONArray(RequestBodyField field) {
        return List.of(DataType.JSON_ARRAY_INT, DataType.JSON_ARRAY_LONG, DataType.JSON_ARRAY_REGEX,
                DataType.JSON_ARRAY_STRING, DataType.JSON_ARRAY_OF_OBJECT).contains(field.getType());
    }

    private void checkMinMax(int min, int max, String fieldValue, String fieldName) throws AppException {
        if (fieldValue == null || fieldValue.length() > max || fieldValue.length() < min) {
            throw new AppException(HttpStatus.BAD_REQUEST.value(),
                    fieldName + " should be greater than " + min + " and less than " + max);
        }
    }

    @FunctionalInterface
    private interface JSONInputValidator {
        void validate() throws AppException;
    }

    private int checkAndGetInt(Object value) {
        return Integer.parseInt(String.valueOf(value));
    }

    private long checkAndGetLong(Object value) {
        return Long.parseLong(String.valueOf(value));
    }

    private boolean checkAndGetBoolean(Object value) throws AppException {
        if (value == null || (!value.equals("false") && !value.equals("true"))) {
            throw new NullValueException(HttpStatus.BAD_REQUEST.value(), "Invalid boolean value => " + value);
        }
        return Boolean.parseBoolean(String.valueOf(value));
    }

    private String checkAndGetString(Object value) throws AppException {
        if (value == null) {
            throw new NullValueException(HttpStatus.BAD_REQUEST.value(), "Null value for string!");
        }
        return String.valueOf(value);
    }

    private JSONObject checkAndGetJSONObject(Object value) throws AppException {
        if (value == null) {
            throw new NullValueException(HttpStatus.BAD_REQUEST.value(), "Null value for JSONObject!");
        }
        return (JSONObject) value;
    }

    private JSONArray checkAndGetJSONArray(Object value) throws AppException {
        if (value == null) {
            throw new NullValueException(HttpStatus.BAD_REQUEST.value(), "Null value for JSONArray!");
        }
        return (JSONArray) value;
    }

    private JSONArray optJSONArray(JSONObject json, String key) {
        Object value = json.get(key);
        if (value == null || !(value instanceof JSONArray)) {
            return null;
        }
        return (JSONArray) value;
    }
}
