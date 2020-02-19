package net.bytebutcher.burp.quicker.context.gui.crawler;

import com.google.common.collect.Maps;
import net.bytebutcher.burp.quicker.context.gui.model.Tab;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.Map;
import java.util.Set;

public class TabsCrawler implements ICrawler {

    private final Component tab;

    public TabsCrawler(Component tab) {
        this.tab = tab;
    }

    public void selectTab(String fullName) {
        getTab(fullName).select();
    }

    public Set<String> getTabCaptions() {
        return getTabs().keySet();
    }

    private Tab getTab(String fullName) {
        return getTabs().get(fullName);
    }

    public Map<String, JMenuItem> getContextMenuEntries() {
        Map<String, JMenuItem> menuEntries = Maps.newHashMap();
        Map<String, Tab> tabs = getTabs();
        for (String tabPath : tabs.keySet()) {
            Tab tab = tabs.get(tabPath);
            JMenuItem item = new JMenuItem();
            item.setAction(new AbstractAction(tab.getFullName()) {
                @Override
                public void actionPerformed(ActionEvent e) {
                    tab.select();
                }
            });
            menuEntries.put("Tab > " + tabPath, item);
        }
        return menuEntries;
    }

    public Map<String, Tab> getTabs() {
        return getTabs(tab, 0, 3, null);
    }

    private Map<String, Tab> getTabs(Component component, int depth, int maxDepth, Tab parentTab) {
        Map<String, Tab> components = Maps.newLinkedHashMap();
        if (depth == maxDepth) {
            return components;
        }
        if (component instanceof Container) {
            if (component instanceof JTabbedPane) {
                JTabbedPane tabbedPane = (JTabbedPane) component;
                for (int i = 0; i < tabbedPane.getTabCount(); i++) {
                    Tab tab = new Tab(parentTab, tabbedPane, i);
                    components.put(tab.getFullName(), tab);
                    components.putAll(getTabs(((JTabbedPane) component).getComponentAt(i), depth + 1, maxDepth, tab));
                }
            } else {
                Component[] childComponents = ((Container) component).getComponents();
                for (Component childComponent : childComponents) {
                    components.putAll(getTabs(childComponent, depth, maxDepth, parentTab));
                }
            }
        }
        return components;
    }
}
