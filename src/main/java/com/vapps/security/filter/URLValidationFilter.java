package com.vapps.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vapps.security.config.PathVariable;
import com.vapps.security.config.URLConfig;
import com.vapps.security.config.WebSecurityConfiguration;
import com.vapps.security.dto.ErrorResponse;
import com.vapps.security.exception.AppException;
import com.vapps.security.service.URLValidationService;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
public class URLValidationFilter implements Filter {

    @Autowired
    private URLValidationService urlValidationService;

    @Autowired(required = false)
    private WebSecurityConfiguration securityConfig;

    @Autowired
    private AntPathMatcher antPathMatcher;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private static final Logger LOGGER = LoggerFactory.getLogger(URLValidationFilter.class);

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        if (securityConfig == null) {
            LOGGER.info("URL configurations (WebSecurityConfiguration) bean is null!");
            return;
        }
        validateURLConfigurations();
        LOGGER.info("Validated security configurations!");
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {
        if (securityConfig == null) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        try {
            LOGGER.info("Intercepting request {} for validation", request.getServletPath());
            /**
             * Using a cached request because if I use the InputStream directly from the request and pass the
             * same request the Filter chain. Then when SpringBoot try to read the InputStream it will get
             * -1 because we have already read it.
             */
            CachedBodyHttpServletRequest cachedBodyHttpServletRequest = new CachedBodyHttpServletRequest(request);
            urlValidationService.validateURL(cachedBodyHttpServletRequest);

            filterChain.doFilter(cachedBodyHttpServletRequest, servletResponse);
        } catch (AppException ex) {

            response.setStatus(ex.getStatus());
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");

            ErrorResponse errorResponse = new ErrorResponse();
            errorResponse.setError(ex.getMessage());
            errorResponse.setStatus(ex.getStatus());
            errorResponse.setPath(request.getServletPath());
            errorResponse.setTime(LocalDateTime.now().toString());

            response.getWriter().println(objectMapper.writeValueAsString(errorResponse));
        }
    }

    private void validateURLConfigurations() {
        checkDuplicateURLConfigs();
        validatePathVariables();
    }

    private void checkDuplicateURLConfigs() {
        List<URLConfig> configs = securityConfig.getUrlConfigs();
        Set<String> urlPathMethods = new HashSet<>();
        for (URLConfig urlConfig : configs) {
            if (!urlPathMethods.add(generateUniqueKey(urlConfig.getPath(), urlConfig.getMethod()))) {
                LOGGER.error("Duplicate URL configuration for URL {}, method {}!", urlConfig.getPath(),
                        urlConfig.getMethod());
                exit();
            }
        }
    }

    private void validatePathVariables() {
        for (URLConfig urlConfig : securityConfig.getUrlConfigs()) {
            Set<String> pathVariableNames = getPathVariableNames(urlConfig.getPath());
            for (PathVariable pathVariable : urlConfig.getPathVariables()) {
                if (!pathVariableNames.contains(pathVariable.getName())) {
                    LOGGER.error("Given path variable {} is not present in the url path {}", pathVariable.getName(),
                            urlConfig.getPath());
                    exit();
                }
            }
        }
    }

    public Set<String> getPathVariableNames(String pathPattern) {
        // Creating a dummy path to extract variable names
        String dummyPath = createDummyPath(pathPattern);

        // Extracting path variables
        Map<String, String> pathVariables = antPathMatcher.extractUriTemplateVariables(pathPattern, dummyPath);

        return pathVariables.keySet();
    }

    private String createDummyPath(String pathPattern) {
        return pathPattern.replaceAll("\\{[^/]+\\}", "dummy");
    }

    private String generateUniqueKey(String path, HttpMethod method) {
        return method.name() + "::" + path;
    }

    private void exit() {
        System.exit(1);
    }
}
