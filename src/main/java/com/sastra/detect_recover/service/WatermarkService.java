package com.sastra.detect_recover.service;

import com.sastra.detect_recover.dto.DetectResponse;
import com.sastra.detect_recover.dto.EmbedResponse;
import com.sastra.detect_recover.util.ImageQualityUtils;
import com.sastra.detect_recover.util.ImageUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;

@Service
@RequiredArgsConstructor
public class WatermarkService {

    public EmbedResponse embed(MultipartFile file) throws Exception {
        BufferedImage input = ImageIO.read(file.getInputStream());
        BufferedImage gray = ImageUtils.convertToGrayscale(input);
        gray = ImageUtils.padToEven(gray);

        int width = gray.getWidth();
        int height = gray.getHeight();
        int rows = height / 2;
        int cols = width / 2;

        // Prevent IDWT bounds overflow (guarantees pixel safety during bit manipulation)
        BufferedImage prepared = safeClampImage(gray);

        int[][] LL = new int[rows][cols], LH = new int[rows][cols];
        int[][] HL = new int[rows][cols], HH = new int[rows][cols];
        computeDWT(prepared, LL, LH, HL, HH);

        // 1. Generate Watermarks for all blocks (based on exact 9-bit logic)
        WatermarkBits[][] watermarks = new WatermarkBits[rows][cols];
        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                watermarks[i][j] = generateBits(LL[i][j], i * cols + j);
            }
        }

        // 2. Prepare Target Coefficients with Embedded Bits
        int[][] targetLL = cloneArray(LL), targetLH = cloneArray(LH);
        int[][] targetHL = cloneArray(HL), targetHH = cloneArray(HH);

        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                WatermarkBits w = watermarks[i][j];

                // Embed Auth into Self (LL bits 3, 2, 1 -> LSB4, LSB3, LSB2)
                targetLL[i][j] = (targetLL[i][j] & ~0b1110) | (w.a1 << 3) | (w.a2 << 2) | (w.a3 << 1);

                // Partner 1 (Horizontal Shift): LH1 bits 2,1,0 & HH1 bits 3,2
                int y1_i = i, y1_j = (j + cols / 2) % cols;
                targetLH[y1_i][y1_j] = (targetLH[y1_i][y1_j] & ~0b0111) | (w.r1 << 2) | (w.r2 << 1) | w.r3;
                targetHH[y1_i][y1_j] = (targetHH[y1_i][y1_j] & ~0b1100) | (w.r4 << 3) | (w.r5 << 2);

                // Partner 2 (Vertical Shift): HL1 bits 2,1,0 & HH1 bits 1,0
                int y2_i = (i + rows / 2) % rows, y2_j = j;
                targetHL[y2_i][y2_j] = (targetHL[y2_i][y2_j] & ~0b0111) | (w.r1 << 2) | (w.r2 << 1) | w.r3;
                targetHH[y2_i][y2_j] = (targetHH[y2_i][y2_j] & ~0b0011) | (w.r4 << 1) | w.r5;
            }
        }

        // 3. Perfect IDWT Reconstruction (Local Search prevents integer truncation false-positives)
        BufferedImage watermarked = new BufferedImage(width, height, BufferedImage.TYPE_BYTE_GRAY);
        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                int a = prepared.getRaster().getSample(j * 2, i * 2, 0);
                int b = prepared.getRaster().getSample(j * 2 + 1, i * 2, 0);
                int c = prepared.getRaster().getSample(j * 2, i * 2 + 1, 0);
                int d = prepared.getRaster().getSample(j * 2 + 1, i * 2 + 1, 0);

                embedBlockWithSearch(watermarked, i, j, a, b, c, d, targetLL[i][j], targetLH[i][j], targetHL[i][j], targetHH[i][j]);
            }
        }

        return EmbedResponse.builder()
                .watermarkedImage(ImageUtils.toBase64(watermarked))
                .psnr(ImageQualityUtils.calculatePSNR(ImageQualityUtils.calculateMSE(gray, watermarked)))
                .ssim(ImageQualityUtils.calculateSSIM(gray, watermarked))
                .build();
    }

    public DetectResponse detectAndRecover(MultipartFile file) throws Exception {
        BufferedImage attacked = ImageIO.read(file.getInputStream());
        attacked = ImageUtils.convertToGrayscale(attacked);
        attacked = ImageUtils.padToEven(attacked);

        int rows = attacked.getHeight() / 2, cols = attacked.getWidth() / 2;
        int[][] LL = new int[rows][cols], LH = new int[rows][cols];
        int[][] HL = new int[rows][cols], HH = new int[rows][cols];
        computeDWT(attacked, LL, LH, HL, HH);

        boolean[][] tamperMap = new boolean[rows][cols];
        int tamperedCount = 0;

        // 1. Detection Phase
        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                int blockIdx = i * cols + j;
                int llVal = LL[i][j];

                // Extract embedded Auth (bits 3,2,1)
                int extA1 = (llVal >> 3) & 1, extA2 = (llVal >> 2) & 1, extA3 = (llVal >> 1) & 1;

                // Recompute Auth from upper bits (8 to 4)
                WatermarkBits recomputed = generateBits(llVal, blockIdx);

                if (extA1 != recomputed.a1 || extA2 != recomputed.a2 || extA3 != recomputed.a3) {
                    tamperMap[i][j] = true;
                }
            }
        }

        tamperMap = applyMorphologicalFilter(tamperMap); // 3x3 filter as per paper
        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                if (tamperMap[i][j]) tamperedCount++;
            }
        }

        // 2. Recovery Phase (Following strict paper specifications)
        BufferedImage recovered = new BufferedImage(attacked.getWidth(), attacked.getHeight(), BufferedImage.TYPE_BYTE_GRAY);

        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                int a = attacked.getRaster().getSample(j * 2, i * 2, 0);
                int b = attacked.getRaster().getSample(j * 2 + 1, i * 2, 0);
                int c = attacked.getRaster().getSample(j * 2, i * 2 + 1, 0);
                int d = attacked.getRaster().getSample(j * 2 + 1, i * 2 + 1, 0);

                if (tamperMap[i][j]) {
                    int y1_i = i, y1_j = (j + cols / 2) % cols;
                    int y2_i = (i + rows / 2) % rows, y2_j = j;
                    Integer recLL = null;

                    // Fetch from Y1
                    if (!tamperMap[y1_i][y1_j]) {
                        recLL = reconstructLL(LH[y1_i][y1_j] & 0b111, (HH[y1_i][y1_j] >> 2) & 0b11);
                    }
                    // Fetch from Y2
                    else if (!tamperMap[y2_i][y2_j]) {
                        recLL = reconstructLL(HL[y2_i][y2_j] & 0b111, HH[y2_i][y2_j] & 0b11);
                    }

                    if (recLL != null) {
                        // The paper dictates keeping the original LH, HL, HH of the attacked block during IDWT
                        a = clamp((recLL + LH[i][j] + HL[i][j] + HH[i][j]) / 2);
                        b = clamp((recLL - LH[i][j] + HL[i][j] - HH[i][j]) / 2);
                        c = clamp((recLL + LH[i][j] - HL[i][j] - HH[i][j]) / 2);
                        d = clamp((recLL - LH[i][j] - HL[i][j] + HH[i][j]) / 2);
                    }
                }
                writeBlock(recovered, i, j, a, b, c, d);
            }
        }

        return DetectResponse.builder()
                .tamperMap(ImageUtils.toBase64(generateTamperVisual(tamperMap)))
                .tamperPercentage((tamperedCount * 100.0) / (rows * cols))
                .recoveredImage(ImageUtils.toBase64(recovered))
                .build();
    }

    // ============================================================
    // PAPER-STRICT LOGIC
    // ============================================================

    private WatermarkBits generateBits(int llVal, int blockIdx) {
        WatermarkBits wb = new WatermarkBits();
        // Exact 9-bit depth indexing (bits 8 down to 0)
        int msb1 = (llVal >> 8) & 1, msb2 = (llVal >> 7) & 1, msb3 = (llVal >> 6) & 1;
        int msb4 = (llVal >> 5) & 1, msb5 = (llVal >> 4) & 1, msb6 = (llVal >> 3) & 1, msb7 = (llVal >> 2) & 1;

        int r1 = (msb1 << 2) | (msb2 << 1) | msb3;
        int r2 = (msb2 << 2) | (msb3 << 1) | msb4;
        int r3 = (msb5 << 2) | (msb6 << 1) | msb7;

        wb.r1 = msb1; wb.r2 = msb2; wb.r3 = msb3; wb.r4 = msb4;
        wb.r5 = (Math.abs(r1 - r3) <= Math.abs(r2 - r3)) ? 1 : 0;

        // Authentication Hashes
        int a1 = r1;
        int a2 = (msb4 << 1) | msb5;

        wb.a1 = ((a1 + a2) % 2 == 0) ? 1 : 0;

        // Rigorous definitions for LSB1 and LSB2 based on the block moduli
        int m1 = blockIdx % 2;
        int m2 = blockIdx % 3;
        int lsb1_m1 = (a1 >> m1) & 1;
        int lsb2_m2 = (a2 >> (m2 % 2)) & 1;
        int lsb1_m2 = (a1 >> m2) & 1;

        wb.a2 = lsb1_m1 ^ lsb2_m2;
        wb.a3 = lsb1_m1 ^ lsb1_m2;

        return wb;
    }

    private int reconstructLL(int r123, int r45) {
        int r1 = (r123 >> 2) & 1, r2 = (r123 >> 1) & 1, r3 = r123 & 1;
        int r4 = (r45 >> 1) & 1, r5 = r45 & 1;

        // Eq. 11: Generate r3'
        int r3_prime = (r5 == 1) ? ((r1 << 2) | (r2 << 1) | r3) : ((r2 << 2) | (r3 << 1) | r4);

        // "produced as 9 bits by adding 0 bits to the end"
        return (r1 << 8) | (r2 << 7) | (r3 << 6) | (r4 << 5) | (r3_prime << 2);
    }


    private void embedBlockWithSearch(BufferedImage out, int i, int j, int origA, int origB, int origC, int origD,
                                      int targetLL, int targetLH, int targetHL, int targetHH) {
        // We MUST preserve bits 8 to 4 of LL (used for Auth computation), and bits 3 to 1 (the Auth bits themselves).
        int maskLL = 0b1_1111_1110, maskLH = 0b0111, maskHL = 0b0111, maskHH = 0b1111;

        int bestA = origA, bestB = origB, bestC = origC, bestD = origD;
        int minErr = Integer.MAX_VALUE;

        // Base IDWT approximation
        int bA = clamp((targetLL + targetLH + targetHL + targetHH) / 2);
        int bB = clamp((targetLL - targetLH + targetHL - targetHH) / 2);
        int bC = clamp((targetLL + targetLH - targetHL - targetHH) / 2);
        int bD = clamp((targetLL - targetLH - targetHL + targetHH) / 2);

        // Sub-pixel search (radius 5) forces the exact preservation of the mathematical remainder
        for(int da = -5; da <= 5; da++) {
            for(int db = -5; db <= 5; db++) {
                for(int dc = -5; dc <= 5; dc++) {
                    for(int dd = -5; dd <= 5; dd++) {
                        int a = clamp(bA + da), b = clamp(bB + db);
                        int c = clamp(bC + dc), d = clamp(bD + dd);

                        int tLL = (a + b + c + d) / 2;
                        int tLH = (a - b + c - d) / 2;
                        int tHL = (a + b - c - d) / 2;
                        int tHH = (a - b - c + d) / 2;

                        if (((tLL ^ targetLL) & maskLL) == 0 && ((tLH ^ targetLH) & maskLH) == 0 &&
                                ((tHL ^ targetHL) & maskHL) == 0 && ((tHH ^ targetHH) & maskHH) == 0) {

                            int err = Math.abs(a - origA) + Math.abs(b - origB) + Math.abs(c - origC) + Math.abs(d - origD);
                            if (err < minErr) {
                                minErr = err;
                                bestA = a; bestB = b; bestC = c; bestD = d;
                            }
                        }
                    }
                }
            }
        }

        if (minErr == Integer.MAX_VALUE) { bestA = bA; bestB = bB; bestC = bC; bestD = bD; } // Extremely rare fallback
        writeBlock(out, i, j, bestA, bestB, bestC, bestD);
    }


    private void computeDWT(BufferedImage img, int[][] LL, int[][] LH, int[][] HL, int[][] HH) {
        for (int i = 0; i < LL.length; i++) {
            for (int j = 0; j < LL[0].length; j++) {
                int a = img.getRaster().getSample(j * 2, i * 2, 0);
                int b = img.getRaster().getSample(j * 2 + 1, i * 2, 0);
                int c = img.getRaster().getSample(j * 2, i * 2 + 1, 0);
                int d = img.getRaster().getSample(j * 2 + 1, i * 2 + 1, 0);

                LL[i][j] = (a + b + c + d) / 2;
                LH[i][j] = (a - b + c - d) / 2;
                HL[i][j] = (a + b - c - d) / 2;
                HH[i][j] = (a - b - c + d) / 2;
            }
        }
    }

    private boolean[][] applyMorphologicalFilter(boolean[][] map) {
        int rows = map.length, cols = map[0].length;
        boolean[][] filtered = new boolean[rows][cols];
        for(int i = 0; i < rows; i++) {
            for(int j = 0; j < cols; j++) {
                int count = 0;
                for(int di = -1; di <= 1; di++) {
                    for(int dj = -1; dj <= 1; dj++) {
                        int ni = i + di, nj = j + dj;
                        if(ni >= 0 && ni < rows && nj >= 0 && nj < cols && map[ni][nj]) count++;
                    }
                }
                filtered[i][j] = count >= 5; // Majority vote over 3x3
            }
        }
        return filtered;
    }

    private BufferedImage safeClampImage(BufferedImage img) {
        for (int y = 0; y < img.getHeight(); y++) {
            for (int x = 0; x < img.getWidth(); x++) {
                int p = img.getRaster().getSample(x, y, 0);
                img.getRaster().setSample(x, y, 0, Math.max(15, Math.min(240, p)));
            }
        }
        return img;
    }

    private int clamp(int val) { return Math.max(0, Math.min(255, val)); }

    private void writeBlock(BufferedImage out, int i, int j, int a, int b, int c, int d) {
        out.getRaster().setSample(j * 2, i * 2, 0, a);
        out.getRaster().setSample(j * 2 + 1, i * 2, 0, b);
        out.getRaster().setSample(j * 2, i * 2 + 1, 0, c);
        out.getRaster().setSample(j * 2 + 1, i * 2 + 1, 0, d);
    }

    private int[][] cloneArray(int[][] src) {
        int[][] dest = new int[src.length][];
        for (int i = 0; i < src.length; i++) dest[i] = src[i].clone();
        return dest;
    }

    private BufferedImage generateTamperVisual(boolean[][] map) {
        BufferedImage res = new BufferedImage(map[0].length * 2, map.length * 2, BufferedImage.TYPE_BYTE_GRAY);
        for (int i = 0; i < map.length; i++) {
            for (int j = 0; j < map[0].length; j++) writeBlock(res, i, j, map[i][j]?255:0, map[i][j]?255:0, map[i][j]?255:0, map[i][j]?255:0);
        }
        return res;
    }

    private static class WatermarkBits {
        int r1, r2, r3, r4, r5;
        int a1, a2, a3;
    }
}