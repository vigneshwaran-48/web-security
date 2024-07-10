package com.vapps.security.config;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class URLParamConfig implements Field {

    private String name;
    private DataType type = DataType.STRING;
    private boolean isMandatory;
    private boolean isMultiple;
    private String regex;
    private int minLength;
    private int maxLength = Integer.MAX_VALUE;

}
