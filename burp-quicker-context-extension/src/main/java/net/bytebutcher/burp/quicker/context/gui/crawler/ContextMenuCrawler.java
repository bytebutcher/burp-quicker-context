package net.bytebutcher.burp.quicker.context.gui.crawler;

import burp.BurpExtender;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import net.bytebutcher.burp.quicker.context.gui.util.BurpColorUtil;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ContextMenuCrawler {

    private static class ContextMenuEntry {

        private String fullPath;
        private final List<String> path;
        private final JMenuItem menuItem;

        public ContextMenuEntry(List<String> path, JMenuItem menuItem) {
            this.path = path;
            this.menuItem = menuItem;
        }

        public JMenuItem getMenuItem() {
            return this.menuItem;
        }

        public List<String> getPath() {
            return Lists.newArrayList(path);
        }

        public String getFullPath() {
            if (fullPath == null) {
                fullPath = Stream.concat(path.stream(), Stream.of(getText())).collect(Collectors.joining(" > "));
            }
            return fullPath;
        }

        public String getText() {
            if (path.size() == 1 && path.get(0).equals("Highlight")) {
                // The 'Highlight' menu entries behave a bit different than the other entries.
                // Since the text of each menu entry is the same, the background color needs to be used to differentiate
                // between the entries. Since Burp does not use any well-known color-schema (e.g. HTML-Colors) and there
                // is no color-to-color-name-mapping for all 256*256*256 colors, this extension defines a custom
                // color-to-color-name-mapping.
                // Note, that this may return null if no color-to-color-name-mapping is found which renders this
                // context menu entry invalid (@see isValid()).
                return BurpColorUtil.getName(this.menuItem.getBackground());
            }
            return this.menuItem.getText();
        }

        /**
         * Checks whether the context menu entry has a valid text.
         * @return true, when there is a valid text, or false, when there is no valid text.
         */
        public boolean isValid() {
            return this.getText() != null;
        }

        @Override
        public String toString() {
            return getFullPath();
        }
    }

    public static Map<String, JMenuItem> getContextMenuEntries(Container container, List<String> path) {
        Map<String, JMenuItem> entries = Maps.newLinkedHashMap();
        if (container == null) {
            return entries;
        }

        List<Component> childElements = Lists.newArrayList();
        if (container instanceof JMenu) {
            JMenu menu = (JMenu) container;
            for (int i = 0; i < menu.getItemCount(); i++) {
                childElements.add(menu.getItem(i));
            }
        } else {
            for (int i = 0; i < container.getComponentCount(); i++) {
                childElements.add(container.getComponent(i));
            }
        }

        for (Component childElement : childElements) {
            if (childElement instanceof JMenu) {
                JMenu menu = (JMenu) childElement;
                List<String> newPath = Stream.concat(path.stream(), Stream.of(menu.getText())).collect(Collectors.toList());
                entries.putAll(getContextMenuEntries(menu, newPath));
            } else if (childElement instanceof JMenuItem) {
                ContextMenuEntry contextMenuEntry = new ContextMenuEntry(path, (JMenuItem) childElement);
                if (contextMenuEntry.isValid()) {
                    entries.put(contextMenuEntry.getFullPath(), contextMenuEntry.getMenuItem());
                } else {
                    BurpExtender.printErr("WARNING: Ignoring invalid context menu entry: " + contextMenuEntry);
                }
            }
        }
        entries.remove("Quicker..."); // Inception
        return entries;
    }

}
