package net.bytebutcher.burp.gui.adapter;

import net.bytebutcher.burp.util.ImageUtil;

import javax.swing.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class LabelIconImageHoverAdapter extends MouseAdapter {

    private String resource;
    private String resourceHovered;
    private JLabel label;

    public LabelIconImageHoverAdapter(JLabel label, String resource, String resourceHovered) {
        this.label = label;
        this.resource = resource;
        this.resourceHovered = resourceHovered;
    }

    @Override
    public void mouseEntered(MouseEvent e) {
        label.setIcon(ImageUtil.createImageIcon(resourceHovered, "", 24, 24));
    }

    @Override
    public void mouseExited(MouseEvent e) {
        label.setIcon(ImageUtil.createImageIcon(resource, "", 24, 24));
    }

}
