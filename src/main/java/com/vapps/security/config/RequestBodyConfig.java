package com.vapps.security.config;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class RequestBodyConfig {

    public enum RequestBodyType {
        JSON,
        INPUT_STREAM,
        FORM_DATA
    }

    private RequestBodyType type = RequestBodyType.JSON;
    private List<RequestBodyField> fields = new ArrayList<>();

}
