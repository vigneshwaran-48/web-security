package com.vapps.security.config;

import lombok.Getter;

public enum DataType {

    INTEGER(Integer.class),
    LONG(Long.class),
    STRING(String.class),
    BOOLEAN(Boolean.class),
    REGEX,
    JSON_OBJECT,
    JSON_ARRAY_INT,
    JSON_ARRAY_STRING,
    JSON_ARRAY_REGEX,
    JSON_ARRAY_LONG,
    JSON_ARRAY_OF_OBJECT;

    @Getter
    private Class<?> type;

    DataType() {}

    DataType(Class<?> type) {
        this.type = type;
    }

}
