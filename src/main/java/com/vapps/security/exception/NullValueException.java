package com.vapps.security.exception;

import org.springframework.http.HttpStatus;

public class NullValueException extends AppException {

    public NullValueException() {
        super();
        status = HttpStatus.BAD_REQUEST.value();
    }

    public NullValueException(int status, String message) {
        super(status, message);
    }
}
