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
import java.util.Random;

@Service
@RequiredArgsConstructor
public class WatermarkService {

    private static final long SEED_1 = 123456789L;
    private static final long SEED_2 = 987654321L;

    public EmbedResponse embed(MultipartFile file) throws Exception {
        BufferedImage input = ImageIO.read(file.getInputStream());
        BufferedImage gray = ImageUtils.convertToGrayscale(input);
        gray = ImageUtils.padToEven(gray);

        int width = gray.getWidth();
        int height = gray.getHeight();
        int rows = height / 2;
        int cols = width / 2;
        int totalBlocks = rows * cols;

        BufferedImage prepared = safeClampImage(gray);

        int[][] LL = new int[rows][cols], LH = new int[rows][cols];
        int[][] HL = new int[rows][cols], HH = new int[rows][cols];
        computeDWT(prepared, LL, LH, HL, HH);

        int[] perm1 = generatePermutation(totalBlocks, SEED_1);
        int[] perm2 = generatePermutation(totalBlocks, SEED_2);

        WatermarkBits[][] watermarks = new WatermarkBits[rows][cols];
        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                watermarks[i][j] = generateBits(LL[i][j], i * cols + j);
            }
        }

        int[][] targetLL = cloneArray(LL), targetLH = cloneArray(LH);
        int[][] targetHL = cloneArray(HL), targetHH = cloneArray(HH);

        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                WatermarkBits w = watermarks[i][j];
                int blockIdx = i * cols + j;

                int ll_embed = (w.a1 << 2) | (w.a2 << 1) | w.a3;
                targetLL[i][j] = (targetLL[i][j] & ~0b1110) | (ll_embed << 1);

                int p1_idx = perm1[blockIdx];
                int y1_i = p1_idx / cols;
                int y1_j = p1_idx % cols;

                int lh_embed = (w.r1 << 2) | (w.r2 << 1) | w.r3;
                int hh1_embed = (w.r4 << 1) | w.r5;

                targetLH[y1_i][y1_j] = optimalLsbSubstitute(targetLH[y1_i][y1_j], lh_embed, 0b0111, 0);
                targetHH[y1_i][y1_j] = (targetHH[y1_i][y1_j] & ~0b1100) | (hh1_embed << 2);

                int p2_idx = perm2[blockIdx];
                int y2_i = p2_idx / cols;
                int y2_j = p2_idx % cols;

                int hl_embed = (w.r1 << 2) | (w.r2 << 1) | w.r3;
                int hh2_embed = (w.r4 << 1) | w.r5;

                targetHL[y2_i][y2_j] = optimalLsbSubstitute(targetHL[y2_i][y2_j], hl_embed, 0b0111, 0);
                targetHH[y2_i][y2_j] = (targetHH[y2_i][y2_j] & ~0b0011) | hh2_embed;
            }
        }

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
        int totalBlocks = rows * cols;
        int[][] LL = new int[rows][cols], LH = new int[rows][cols];
        int[][] HL = new int[rows][cols], HH = new int[rows][cols];
        computeDWT(attacked, LL, LH, HL, HH);

        int[] perm1 = generatePermutation(totalBlocks, SEED_1);
        int[] perm2 = generatePermutation(totalBlocks, SEED_2);

        boolean[][] tamperMap = new boolean[rows][cols];
        int tamperedCount = 0;

        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                int blockIdx = i * cols + j;
                int llVal = LL[i][j];

                int extA1 = (llVal >> 3) & 1, extA2 = (llVal >> 2) & 1, extA3 = (llVal >> 1) & 1;
                WatermarkBits recomputed = generateBits(llVal, blockIdx);

                if (extA1 != recomputed.a1 || extA2 != recomputed.a2 || extA3 != recomputed.a3) {
                    tamperMap[i][j] = true;
                }
            }
        }

        tamperMap = applyMorphologicalFilter(tamperMap);
        boolean[][] recoveredMap = new boolean[rows][cols];

        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                if (tamperMap[i][j]) {
                    tamperedCount++;
                    recoveredMap[i][j] = false;
                } else {
                    recoveredMap[i][j] = true;
                }
            }
        }

        BufferedImage recovered = new BufferedImage(attacked.getWidth(), attacked.getHeight(), BufferedImage.TYPE_BYTE_GRAY);

        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                int a = attacked.getRaster().getSample(j * 2, i * 2, 0);
                int b = attacked.getRaster().getSample(j * 2 + 1, i * 2, 0);
                int c = attacked.getRaster().getSample(j * 2, i * 2 + 1, 0);
                int d = attacked.getRaster().getSample(j * 2 + 1, i * 2 + 1, 0);

                if (tamperMap[i][j]) {
                    int blockIdx = i * cols + j;

                    int p1_idx = perm1[blockIdx];
                    int y1_i = p1_idx / cols;
                    int y1_j = p1_idx % cols;

                    int p2_idx = perm2[blockIdx];
                    int y2_i = p2_idx / cols;
                    int y2_j = p2_idx % cols;

                    Integer recLL = null;

                    if (!tamperMap[y1_i][y1_j]) {
                        recLL = reconstructLL(LH[y1_i][y1_j] & 0b111, (HH[y1_i][y1_j] >> 2) & 0b11);
                    } else if (!tamperMap[y2_i][y2_j]) {
                        recLL = reconstructLL(HL[y2_i][y2_j] & 0b111, HH[y2_i][y2_j] & 0b11);
                    }

                    if (recLL != null) {
                        int recoveredPixel = clamp(recLL / 2);
                        a = recoveredPixel; b = recoveredPixel; c = recoveredPixel; d = recoveredPixel;
                        recoveredMap[i][j] = true;
                    } else {
                        a = 0; b = 0; c = 0; d = 0;
                    }
                }
                writeBlock(recovered, i, j, a, b, c, d);
            }
        }

        for (int pass = 0; pass < 2; pass++) {
            boolean[][] nextRecoveredMap = cloneBooleanArray(recoveredMap);
            for (int i = 0; i < rows; i++) {
                for (int j = 0; j < cols; j++) {
                    if (!recoveredMap[i][j]) {
                        int sumA = 0, sumB = 0, sumC = 0, sumD = 0, count = 0;
                        for (int di = -1; di <= 1; di++) {
                            for (int dj = -1; dj <= 1; dj++) {
                                int ni = i + di, nj = j + dj;
                                if (ni >= 0 && ni < rows && nj >= 0 && nj < cols && recoveredMap[ni][nj]) {
                                    sumA += recovered.getRaster().getSample(nj * 2, ni * 2, 0);
                                    sumB += recovered.getRaster().getSample(nj * 2 + 1, ni * 2, 0);
                                    sumC += recovered.getRaster().getSample(nj * 2, ni * 2 + 1, 0);
                                    sumD += recovered.getRaster().getSample(nj * 2 + 1, ni * 2 + 1, 0);
                                    count++;
                                }
                            }
                        }
                        if (count > 0) {
                            writeBlock(recovered, i, j, sumA/count, sumB/count, sumC/count, sumD/count);
                            nextRecoveredMap[i][j] = true;
                        }
                    }
                }
            }
            recoveredMap = nextRecoveredMap;
        }

        return DetectResponse.builder()
                .tamperMap(ImageUtils.toBase64(generateTamperVisual(tamperMap)))
                .tamperPercentage((tamperedCount * 100.0) / (rows * cols))
                .recoveredImage(ImageUtils.toBase64(recovered))
                .build();
    }

    // ============================================================
    // UTILITY & MATHEMATICAL METHODS
    // ============================================================

    private int[] generatePermutation(int size, long seed) {
        int[] perm = new int[size];
        for (int i = 0; i < size; i++) perm[i] = i;
        Random rnd = new Random(seed);
        for (int i = size - 1; i > 0; i--) {
            int j = rnd.nextInt(i + 1);
            int temp = perm[i];
            perm[i] = perm[j];
            perm[j] = temp;
        }
        return perm;
    }

    private int optimalLsbSubstitute(int original, int embeddedBits, int mask, int shift) {
        int replaced = (original & ~mask) | (embeddedBits << shift);
        int step = Integer.highestOneBit(mask) << 1;

        int opt1 = replaced;
        int opt2 = replaced + step;
        int opt3 = replaced - step;

        int d1 = Math.abs(original - opt1);
        int d2 = Math.abs(original - opt2);
        int d3 = Math.abs(original - opt3);

        if (d1 <= d2 && d1 <= d3) return opt1;
        if (d2 <= d1 && d2 <= d3) return opt2;
        return opt3;
    }

    private WatermarkBits generateBits(int llVal, int blockIdx) {
        WatermarkBits wb = new WatermarkBits();
        int msb1 = (llVal >> 8) & 1, msb2 = (llVal >> 7) & 1, msb3 = (llVal >> 6) & 1;
        int msb4 = (llVal >> 5) & 1, msb5 = (llVal >> 4) & 1, msb6 = (llVal >> 3) & 1, msb7 = (llVal >> 2) & 1;

        // 1. Generate Recovery Bits (Preserved from original logic)
        int r1 = (msb1 << 2) | (msb2 << 1) | msb3;
        int r2 = (msb2 << 2) | (msb3 << 1) | msb4;
        int r3 = (msb5 << 2) | (msb6 << 1) | msb7;

        wb.r1 = msb1; wb.r2 = msb2; wb.r3 = msb3; wb.r4 = msb4;
        wb.r5 = (Math.abs(r1 - r3) <= Math.abs(r2 - r3)) ? 1 : 0;

        // 2. NEW: Cryptographic Spatial Authentication (Defeats Copy-Move)
        // Strictly uses only the top 5 bits (bits unaffected by embedding)
        int top5Bits = (llVal >> 4) & 0b11111;

        // Integer Avalanche Hash (Murmur3 Finalizer logic)
        // This completely scrambles the structural bits with the exact spatial location
        int hash = (top5Bits * 31) + blockIdx;
        hash ^= (hash >>> 16);
        hash *= 0x85ebca6b;
        hash ^= (hash >>> 13);
        hash *= 0xc2b2ae35;
        hash ^= (hash >>> 16);

        wb.a1 = (hash >> 2) & 1;
        wb.a2 = (hash >> 1) & 1;
        wb.a3 = hash & 1;

        return wb;
    }

    private int reconstructLL(int r123, int r45) {
        int r1 = (r123 >> 2) & 1, r2 = (r123 >> 1) & 1, r3 = r123 & 1;
        int r4 = (r45 >> 1) & 1, r5 = r45 & 1;

        int r3_prime = (r5 == 1) ? ((r1 << 2) | (r2 << 1) | r3) : ((r2 << 2) | (r3 << 1) | r4);
        return (r1 << 8) | (r2 << 7) | (r3 << 6) | (r4 << 5) | (r3_prime << 2);
    }

    private void embedBlockWithSearch(BufferedImage out, int i, int j, int origA, int origB, int origC, int origD,
                                      int targetLL, int targetLH, int targetHL, int targetHH) {
        int maskLL = 0b1_1111_1110, maskLH = 0b0111, maskHL = 0b0111, maskHH = 0b1111;

        int bestA = origA, bestB = origB, bestC = origC, bestD = origD;
        int minErr = Integer.MAX_VALUE;

        int bA = clamp((targetLL + targetLH + targetHL + targetHH) / 2);
        int bB = clamp((targetLL - targetLH + targetHL - targetHH) / 2);
        int bC = clamp((targetLL + targetLH - targetHL - targetHH) / 2);
        int bD = clamp((targetLL - targetLH - targetHL + targetHH) / 2);

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

        if (minErr == Integer.MAX_VALUE) { bestA = bA; bestB = bB; bestC = bC; bestD = bD; }
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
                filtered[i][j] = count >= 2;
            }
        }
        return filtered;
    }

    private BufferedImage safeClampImage(BufferedImage img) {
        for (int y = 0; y < img.getHeight(); y++) {
            for (int x = 0; x < img.getWidth(); x++) {
                int p = img.getRaster().getSample(x, y, 0);
                img.getRaster().setSample(x, y, 0, Math.max(5, Math.min(250, p)));
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

    private boolean[][] cloneBooleanArray(boolean[][] src) {
        boolean[][] dest = new boolean[src.length][];
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