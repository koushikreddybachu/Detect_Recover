package com.sastra.detect_recover.util;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;

public class ImageUtils {

    public static BufferedImage convertToGrayscale(BufferedImage input) {
        BufferedImage gray = new BufferedImage(
                input.getWidth(),
                input.getHeight(),
                BufferedImage.TYPE_BYTE_GRAY
        );

        Graphics g = gray.getGraphics();
        g.drawImage(input, 0, 0, null);
        g.dispose();

        return gray;
    }

    public static BufferedImage padToEven(BufferedImage input) {

        int width = input.getWidth();
        int height = input.getHeight();

        int newWidth = (width % 2 == 0) ? width : width + 1;
        int newHeight = (height % 2 == 0) ? height : height + 1;

        if (newWidth == width && newHeight == height) {
            return input;
        }

        BufferedImage padded = new BufferedImage(
                newWidth,
                newHeight,
                BufferedImage.TYPE_BYTE_GRAY
        );

        Graphics g = padded.getGraphics();
        g.drawImage(input, 0, 0, null);
        g.dispose();

        return padded;
    }

    public static String toBase64(BufferedImage image) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, "png", baos);
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }
}
