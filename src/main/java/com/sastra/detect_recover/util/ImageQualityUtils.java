package com.sastra.detect_recover.util;

import java.awt.image.BufferedImage;

public class ImageQualityUtils {

    private static final double MAX_PIXEL = 255.0;

    // =========================
    // MSE
    // =========================
    public static double calculateMSE(BufferedImage original, BufferedImage processed) {

        int width = original.getWidth();
        int height = original.getHeight();

        double mse = 0.0;

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {

                int orig = original.getRaster().getSample(x, y, 0);
                int proc = processed.getRaster().getSample(x, y, 0);

                double diff = orig - proc;
                mse += diff * diff;
            }
        }

        mse /= (width * height);
        return mse;
    }

    // =========================
    // PSNR
    // =========================
    public static double calculatePSNR(double mse) {

        if (mse == 0) {
            // Avoid Infinity crashing frontend
            return 100.0;
        }

        return 10 * Math.log10((MAX_PIXEL * MAX_PIXEL) / mse);
    }

    // =========================
    // SSIM (Global Implementation)
    // =========================
    public static double calculateSSIM(BufferedImage img1, BufferedImage img2) {

        int width = img1.getWidth();
        int height = img1.getHeight();
        int N = width * height;

        double mean1 = 0.0;
        double mean2 = 0.0;

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {

                mean1 += img1.getRaster().getSample(x, y, 0);
                mean2 += img2.getRaster().getSample(x, y, 0);
            }
        }

        mean1 /= N;
        mean2 /= N;

        double variance1 = 0.0;
        double variance2 = 0.0;
        double covariance = 0.0;

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {

                double pixel1 = img1.getRaster().getSample(x, y, 0);
                double pixel2 = img2.getRaster().getSample(x, y, 0);

                variance1 += Math.pow(pixel1 - mean1, 2);
                variance2 += Math.pow(pixel2 - mean2, 2);
                covariance += (pixel1 - mean1) * (pixel2 - mean2);
            }
        }

        variance1 /= (N - 1);
        variance2 /= (N - 1);
        covariance /= (N - 1);

        double C1 = Math.pow(0.01 * MAX_PIXEL, 2);
        double C2 = Math.pow(0.03 * MAX_PIXEL, 2);

        double numerator =
                (2 * mean1 * mean2 + C1) *
                        (2 * covariance + C2);

        double denominator =
                (mean1 * mean1 + mean2 * mean2 + C1) *
                        (variance1 + variance2 + C2);

        return numerator / denominator;
    }
}
