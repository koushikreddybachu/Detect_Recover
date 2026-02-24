package com.sastra.detect_recover.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class EmbedResponse {

    private String watermarkedImage;
    private double psnr;
    private double ssim;
}
