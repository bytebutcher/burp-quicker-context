package net.bytebutcher.burp.quicker.context.gui.processor;

import com.google.common.collect.Lists;
import net.bytebutcher.burp.quicker.context.gui.model.ContextMenuEvent;

import javax.swing.*;
import java.awt.event.ActionListener;
import java.util.Map;

public class ContextMenuProcessor {

    public static void process(String selectedItem, Map<String, JMenuItem> contextMenuEntries, ContextMenuEvent contextMenuEvent) {
        if (contextMenuEntries.get(selectedItem) != null) {
            for (ActionListener actionListener : contextMenuEntries.get(selectedItem).getActionListeners()) {
                actionListener.actionPerformed(contextMenuEvent.getActionEvent());
            }
        }
    }

}
