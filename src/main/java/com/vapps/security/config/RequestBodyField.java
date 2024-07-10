package com.vapps.security.config;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class RequestBodyField implements Field {

    private String key;
    private DataType type;
    private List<RequestBodyField> children = new ArrayList<>();
    private String regex;
    private boolean isMandatory;
    private int minLength;
    private int maxLength = Integer.MAX_VALUE;

}
