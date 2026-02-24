package com.sastra.detect_recover.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class DetectResponse {

    private String tamperMap;
    private double tamperPercentage;
    private String recoveredImage;
    private double accuracy;
    private double sensitivity;
    private double recoveryPsnr;
}
