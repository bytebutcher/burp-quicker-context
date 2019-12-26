package net.bytebutcher.burp.quicker.context.gui.crawler;

import burp.BurpExtender;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import net.bytebutcher.burp.quicker.context.gui.model.ContextMenuEvent;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionListener;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ContextMenuCrawler {

    private final BurpExtender burpExtender;

    public ContextMenuCrawler(BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
    }

    public Map<String, JMenuItem> getContextMenuEntries(Container container, List<String> path) {
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
                JMenuItem menuItem = (JMenuItem) childElement;
                String fullPath = Stream.concat(path.stream(), Stream.of(menuItem.getText())).collect(Collectors.joining(" > "));
                entries.put(fullPath, menuItem);
            }
        }
        entries.remove("Quicker..."); // Inception
        return entries;
    }

    public void execute(String selectedItem, ContextMenuEvent contextMenuEvent) {
        Map<String, JMenuItem> contextMenuEntries = getContextMenuEntries(contextMenuEvent.getSource(), Lists.newArrayList());
        if (contextMenuEntries.get(selectedItem) != null) {
            for (ActionListener actionListener : contextMenuEntries.get(selectedItem).getActionListeners()) {
                actionListener.actionPerformed(contextMenuEvent.getActionEvent());
            }
        }
    }
}
