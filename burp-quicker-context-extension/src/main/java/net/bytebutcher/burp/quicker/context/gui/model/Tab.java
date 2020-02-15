package net.bytebutcher.burp.quicker.context.gui.model;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class Tab {

    private final Tab parentTab;
    private JTabbedPane tabbedPane;
    private int index;
    private List<Tab> tabPath;
    private String fullName;

    public Tab(Tab parentTab, JTabbedPane tabbedPane, int index) {
        assert(index >= 0);
        assert(tabbedPane != null);
        this.parentTab = parentTab;
        this.index = index;
        this.tabbedPane = tabbedPane;
    }

    public String getName() {
        return tabbedPane.getTitleAt(this.index);
    }

    public String getFullName() {
        if (fullName == null) {
            fullName = getTabPath().stream().map(Tab::getName).collect(Collectors.joining(" > "));
        }
        return fullName;
    }

    public int getIndex() {
        return index;
    }

    private List<Tab> getTabPath() {
        if (tabPath == null) {
            if (parentTab != null) {
                tabPath = Lists.newArrayList(parentTab.getTabPath());
            } else {
                tabPath = Lists.newArrayList();
            }
            tabPath.add(this);
        }
        return tabPath;
    }

    public int depth() {
        return tabPath.size();
    }

    public JTabbedPane getTabbedPane() {
        return tabbedPane;
    }

    public Component getContentPane() {
        return getTabbedPane().getComponentAt(this.getIndex());
    }

    public void select() {
        getTabPath().stream().forEach(s -> s.getTabbedPane().setSelectedIndex(s.getIndex()));
    }

}
