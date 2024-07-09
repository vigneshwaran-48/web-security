package com.vapps.security.config;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class WebSecurityConfiguration {

    private List<URLConfig> urlConfigs = new ArrayList<>();

}
