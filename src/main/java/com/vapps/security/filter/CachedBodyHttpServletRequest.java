package com.vapps.security.filter;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;

/**
 * Used for cache the request InputStream for SpringBoot to use it again.
 */
public class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

    private byte[] cachedBody;

    private static final Logger LOGGER = LoggerFactory.getLogger(CachedBodyHttpServletRequest.class);

    public CachedBodyHttpServletRequest(HttpServletRequest request) throws IOException {
        super(request);
        try {
            /**
             * Calling this method to populate the parts data before I read the input stream for caching.
             *
             * If we not call this method then when spring boot calls the getParts on this request, Tomcat's Request
             * will not be able to parse the parts because it won't have the input stream at that time.
             *
             * Parsing it now will be stored in a collection in the request object which can be later used by
             * spring boot or our application itself.
             */
            request.getParts();
        } catch (ServletException e) {
            LOGGER.error(e.getMessage(), e);
        }
        InputStream requestInputStream = request.getInputStream();
        this.cachedBody = requestInputStream.readAllBytes();
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        return new CachedBodyServletInputStream(this.cachedBody);
    }

    @Override
    public BufferedReader getReader() throws IOException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(this.cachedBody);
        return new BufferedReader(new InputStreamReader(byteArrayInputStream, getCharacterEncoding()));
    }

    private static class CachedBodyServletInputStream extends ServletInputStream {

        private final ByteArrayInputStream byteArrayInputStream;

        public CachedBodyServletInputStream(byte[] cachedBody) {
            this.byteArrayInputStream = new ByteArrayInputStream(cachedBody);
        }

        @Override
        public boolean isFinished() {
            return byteArrayInputStream.available() == 0;
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(ReadListener readListener) {
            // No implementation needed
        }

        @Override
        public int read() throws IOException {
            return byteArrayInputStream.read();
        }
    }
}