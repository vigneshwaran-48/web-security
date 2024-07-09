package com.vapps.security.dto;

import lombok.Data;

import java.time.LocalDateTime;

@Data
public class ErrorResponse {

    private String path;
    private int status;
    private String error;
    private String time;

}
