package net.bytebutcher.burp.quicker.context.gui.model;

import java.awt.*;
import java.awt.event.ActionEvent;

public class ContextMenuEvent {

    private final Container source;
    private final ActionEvent actionEvent;

    public ContextMenuEvent(Container source, ActionEvent actionEvent) {
        this.source = source;
        this.actionEvent = actionEvent;
    }

    public Container getSource() {
        return source;
    }

    public ActionEvent getActionEvent() {
        return actionEvent;
    }
}
