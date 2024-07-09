package com.vapps.security.config;

import lombok.Data;

import java.util.List;

@Data
public class RequestBodyField {

    private String key;
    private DataType type;
    private List<RequestBodyField> children;
    private String regex;

}
