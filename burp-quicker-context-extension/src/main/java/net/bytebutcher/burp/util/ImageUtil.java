package net.bytebutcher.burp.util;

import javax.swing.*;
import java.awt.*;

public class ImageUtil {

    private static final Class clazz = ImageUtil.class;

    public static ImageIcon createImageIcon(String path, String description, int width, int height) {
        java.net.URL imgURL = clazz.getResource(path);
        if (imgURL != null) {
            ImageIcon icon = new ImageIcon(imgURL);
            Image image = icon.getImage().getScaledInstance(width, height,  Image.SCALE_SMOOTH);
            return new ImageIcon(image, description);
        } else {
            return null;
        }
    }

}
