package com.vapps.security.service;

import com.vapps.security.config.RequestBodyConfig;
import com.vapps.security.config.RequestBodyField;
import com.vapps.security.exception.AppException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.Part;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Collection;
import java.util.Optional;

@Service
public class RequestBodyValidationService {

    public void handleFormData(HttpServletRequest request, RequestBodyConfig config) throws AppException {

        if (!request.getContentType().equals(MediaType.MULTIPART_FORM_DATA.getType())) {
            throw new AppException(HttpStatus.BAD_REQUEST.value(),
                    MediaType.MULTIPART_FORM_DATA.getType() + " is expected!");
        }
        Collection<Part> parts;
        try {
            request.getParts();
        } catch (ServletException | IOException ex) {
            throw new AppException(HttpStatus.BAD_REQUEST.value(), "Unable to parse form data!");
        }

    }

    private void validatePart(Part part, RequestBodyConfig config) throws AppException {
        Optional<RequestBodyField> field = config.getFields().stream()
                .filter(f -> f.getKey().equals(part.getName())).findFirst();
        if (field.isEmpty()) {
            throw new AppException(HttpStatus.BAD_REQUEST.value(), "'" + part.getName() + "' is not allowed!");
        }

    }
}
