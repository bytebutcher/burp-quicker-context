package net.bytebutcher.burp.quicker.context.gui.keystroke;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import com.google.gson.Gson;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.util.Optional;
import java.util.Stack;

public class KeyStrokeManager {

    private final IBurpExtenderCallbacks callbacks;
    private Stack<KeyStrokeListener> keyStrokeListeners = new Stack<>();

    private KeyboardFocusManager focusManager;
    private KeyStrokeDispatcher dispatcher;

    public KeyStroke getKeyBinding() {
        String quickerKeyBinding = this.callbacks.loadExtensionSetting("QuickerKeyBinding");
        if (quickerKeyBinding == null || quickerKeyBinding.isEmpty()) {
            return KeyStroke.getKeyStroke("shift pressed SPACE");
        } else {
            return new Gson().fromJson(quickerKeyBinding, KeyStroke.class);
        }
    }

    public void setKeyBinding(KeyStroke keyStroke) {
        this.callbacks.saveExtensionSetting("QuickerKeyBinding", new Gson().toJson(keyStroke));
    }

    class KeyStrokeDispatcher implements KeyEventDispatcher {

        @Override
        public boolean dispatchKeyEvent(KeyEvent e) {
            if (keyStrokeListeners.peek() != null) {
                KeyStroke keyStroke = KeyStroke.getKeyStroke(e.getKeyCode(), e.getModifiers());
                keyStrokeListeners.peek().dispatchKeyStroke(keyStroke);
            }
            return false;
        }

        @Override
        public boolean equals(Object obj) {
            return obj instanceof KeyStrokeDispatcher;
        }
    }


    public KeyStrokeManager(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager();
        dispatcher = new KeyStrokeDispatcher();
        focusManager.addKeyEventDispatcher(dispatcher);
    }

    public void unload() {
        focusManager.removeKeyEventDispatcher(dispatcher);
    }

    public void push(KeyStrokeListener keyStrokeListener) {
        keyStrokeListeners.push(keyStrokeListener);
    }

    public KeyStrokeListener pop() {
        return keyStrokeListeners.pop();
    }

    public int size() {
        return keyStrokeListeners.size();
    }

}
