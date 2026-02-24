package com.sastra.detect_recover.controller;

import com.sastra.detect_recover.dto.DetectResponse;
import com.sastra.detect_recover.dto.EmbedResponse;
import com.sastra.detect_recover.service.WatermarkService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/watermark")
@RequiredArgsConstructor
@CrossOrigin(origins = "*") // allow React frontend
public class WatermarkController {

    private final WatermarkService watermarkService;

    // =========================
    // EMBED
    // =========================
    @PostMapping("/embed")
    public ResponseEntity<EmbedResponse> embed(
            @RequestParam("image") MultipartFile file
    ) throws Exception {

        EmbedResponse response = watermarkService.embed(file);
        return ResponseEntity.ok(response);
    }

    // =========================
    // DETECT & RECOVER
    // =========================
    @PostMapping("/detect-recover")
    public ResponseEntity<DetectResponse> detectAndRecover(
            @RequestParam("image") MultipartFile file
    ) throws Exception {

        DetectResponse response = watermarkService.detectAndRecover(file);
        return ResponseEntity.ok(response);
    }
}
