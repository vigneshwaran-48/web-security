package com.vapps.security.config;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpMethod;

import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class URLConfig {

    private String path;
    private List<URLParamConfig> params = new ArrayList<>();
    private List<PathVariable> pathVariables = new ArrayList<>();
    private HttpMethod method = HttpMethod.GET;
    private RequestBodyConfig requestBodyConfig;

}
