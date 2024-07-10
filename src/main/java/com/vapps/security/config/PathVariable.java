package com.vapps.security.config;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PathVariable implements Field {

    private String name;
    private DataType type = DataType.STRING;
    private String regex;
    private boolean optional;
    private int minLength;
    private int maxLength = Integer.MAX_VALUE;

}
