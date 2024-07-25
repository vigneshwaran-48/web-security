package com.vapps.security.util;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.util.UrlPathHelper;

public class RequestUtil {

    public static String getServletPath(HttpServletRequest request) {
        return new UrlPathHelper().getPathWithinApplication(request);
    }
}
