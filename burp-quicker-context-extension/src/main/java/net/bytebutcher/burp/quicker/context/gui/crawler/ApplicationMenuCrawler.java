package net.bytebutcher.burp.quicker.context.gui.crawler;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.Map;
import java.util.Stack;

public class ApplicationMenuCrawler implements ICrawler {

    private final JMenuBar menuBar;

    public ApplicationMenuCrawler(JMenuBar menuBar) {
        this.menuBar = menuBar;
    }

    @Override
    public Map<String, JMenuItem> getContextMenuEntries() {
        Map<String, JMenuItem> result = Maps.newHashMap();
        Stack<String> path = new Stack<>();
        for (int i = 0; i < menuBar.getMenuCount(); i++) {
            JMenu menu = menuBar.getMenu(i);
            path.push(menu.getText());
            parseMenu(path, menu, result);
            path.pop();
        }
        return result;
    }

    private void parseMenu(Stack<String> path, Container container, Map<String, JMenuItem> result) {
        List<Component> childElements = getComponents(container);
        for (Component component : childElements) {
            if (component instanceof JMenu) {
                path.push(((JMenu) component).getText());
                parseMenu(path, (JMenu) component, result);
                path.pop();
            } else if (component instanceof JMenuItem) {
                JMenuItem item = (JMenuItem) component;
                path.push(item.getText());
                result.put(String.join(" > ", path), item);
                path.pop();
            } else {
                // Do nothing ...
            }
        }
    }

    private List<Component> getComponents(Container container) {
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
        return childElements;
    }
}
