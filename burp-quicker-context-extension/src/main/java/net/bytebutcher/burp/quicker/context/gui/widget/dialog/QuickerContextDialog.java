package net.bytebutcher.burp.quicker.context.gui.widget.dialog;

import burp.BurpExtender;
import com.google.common.collect.EvictingQueue;
import com.google.common.collect.Lists;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;
import net.bytebutcher.burp.quicker.context.gui.crawler.ContextMenuCrawler;
import net.bytebutcher.burp.quicker.context.gui.model.ContextMenuEvent;
import net.bytebutcher.burp.quicker.context.gui.processor.ContextMenuProcessor;
import net.bytebutcher.burp.quicker.context.gui.util.DialogUtil;
import net.bytebutcher.burp.quicker.context.gui.util.ImageUtil;
import net.bytebutcher.burp.quicker.context.gui.widget.combobox.FilterComboBox;
import net.bytebutcher.burp.quicker.context.model.History;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.HashSet;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

public class QuickerContextDialog extends JDialog {
    protected final BurpExtender burpExtender;
    public JPanel rootComponent;
    protected JComboBox<String> comboBox;
    private JButton btnRun;
    private JLabel lblHistoryNext;
    private JLabel lblHistoryPrev;
    private Map<String, JMenuItem> contextMenuEntries;
    private History history;

    private final ContextMenuEvent contextMenuEvent;

    public QuickerContextDialog(BurpExtender burpExtender, ContextMenuEvent contextMenuEvent) {
        this.burpExtender = burpExtender;
        this.contextMenuEvent = contextMenuEvent;
        $$$setupUI$$$();
        this.setLayout(new BorderLayout());
        this.setContentPane(rootComponent);
        btnRun.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                execute();
                dispose();
            }
        });
        setupHistory();
        registerKeyBoardAction();
        initializeComboBox();
        requestFocus();
        setSize(250, 50);
        pack();
        setModal(true);
        setTitle("Quicker Context");
        setLocation(DialogUtil.getX(burpExtender.getParent(), this), DialogUtil.getY(burpExtender.getParent(), this));
        setVisible(true);
    }

    private void registerKeyBoardAction() {
        comboBox.getEditor().getEditorComponent().addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                switch (e.getKeyCode()) {
                    case KeyEvent.VK_ENTER:
                        execute();
                        dispose();
                        break;
                    case KeyEvent.VK_ESCAPE:
                        dispose();
                        break;
                    default:
                }
            }
        });
        rootComponent.registerKeyboardAction(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                execute();
                dispose();
            }
        }, KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), JComponent.WHEN_IN_FOCUSED_WINDOW);
        rootComponent.registerKeyboardAction(e -> dispose(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_IN_FOCUSED_WINDOW);
    }

    protected void setupHistory() {
        history = new History(getContextMenuEntries(contextMenuEvent).keySet(), burpExtender);
        JTextField textField = (JTextField) comboBox.getEditor().getEditorComponent();
        setupHistoryTraversalKeys(textField, history, burpExtender);
        setupHistoryButtons(textField);
    }

    private void setupHistoryButtons(JTextField textField) {
        this.lblHistoryPrev.setIcon(ImageUtil.createImageIcon("/prev.png", "", 16, 16));
        this.lblHistoryPrev.addMouseListener(new MouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                // Load only history elements which are also present in the context menu
                if (!history.isEmpty()) {
                    textField.setText(history.getPrevious());
                }
            }
        });
        this.lblHistoryNext.setIcon(ImageUtil.createImageIcon("/next.png", "", 16, 16));
        this.lblHistoryNext.addMouseListener(new MouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                if (!history.isEmpty()) {
                    textField.setText(history.getNext());
                }
            }
        });
    }

    public void initializeComboBox() {
        Set<String> contextMenuEntries = getContextMenuEntries(contextMenuEvent).keySet();
        for (String tabCaption : contextMenuEntries) {
            comboBox.addItem(tabCaption);
        }
        if (!history.isEmpty()) {
            SwingUtilities.invokeLater(() -> ((JTextField) comboBox.getEditor().getEditorComponent()).setText(history.getCurrent()));
        }
        SwingUtilities.invokeLater(() -> comboBox.getEditor().selectAll());
    }

    private Map<String, JMenuItem> getContextMenuEntries(ContextMenuEvent contextMenu) {
        if (contextMenuEntries == null) {
            contextMenuEntries = ContextMenuCrawler.getContextMenuEntries(contextMenu.getSource(), Lists
                    .newArrayList());
        }
        return contextMenuEntries;
    }

    private void saveToHistory(String selectedItem) {
        Queue<String> history = EvictingQueue.create(10);
        history.addAll(burpExtender.getConfig().loadHistory());
        while (history.contains(selectedItem)) {
            history.remove(selectedItem);
        }
        history.add(selectedItem);
        burpExtender.getConfig().saveHistory(Lists.newArrayList(history));
    }

    private static void setupHistoryTraversalKeys(JTextField textField, History history, BurpExtender burpExtender) {
        KeyStroke ctrlTab = KeyStroke.getKeyStroke("ctrl TAB");
        KeyStroke ctrlShiftTab = KeyStroke.getKeyStroke("ctrl shift TAB");

        // Remove ctrl-tab from normal focus traversal
        Set<AWTKeyStroke> forwardKeys = new HashSet<AWTKeyStroke>(textField.getFocusTraversalKeys(KeyboardFocusManager.FORWARD_TRAVERSAL_KEYS));
        forwardKeys.remove(ctrlTab);
        textField.setFocusTraversalKeys(KeyboardFocusManager.FORWARD_TRAVERSAL_KEYS, forwardKeys);

        // Remove ctrl-shift-tab from normal focus traversal
        Set<AWTKeyStroke> backwardKeys = new HashSet<AWTKeyStroke>(textField.getFocusTraversalKeys(KeyboardFocusManager.BACKWARD_TRAVERSAL_KEYS));
        backwardKeys.remove(ctrlShiftTab);
        textField.setFocusTraversalKeys(KeyboardFocusManager.BACKWARD_TRAVERSAL_KEYS, backwardKeys);

        // Add keys to the tab's input map
        InputMap inputMap = textField.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        inputMap.put(ctrlTab, "navigateNext");
        textField.getActionMap().put("navigateNext",
                new AbstractAction() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if (!history.isEmpty()) {
                            textField.setText(history.getNext());
                        }
                    }
                });
        inputMap.put(ctrlShiftTab, "navigatePrevious");
        textField.getActionMap().put("navigatePrevious",
                new AbstractAction() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if (!history.isEmpty()) {
                            textField.setText(history.getNext());
                        }
                    }
                });
    }

    public String getSelectedItem() {
        return comboBox.getItemAt(comboBox.getSelectedIndex());
    }

    public void execute() {
        String selectedItem = getSelectedItem();
        saveToHistory(selectedItem);
        ContextMenuProcessor.process(selectedItem, getContextMenuEntries(contextMenuEvent), contextMenuEvent);
    }

    public void requestFocus() {
        comboBox.requestFocus();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        createUIComponents();
        rootComponent = new JPanel();
        rootComponent.setLayout(new BorderLayout(0, 0));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(1, 3, new Insets(0, 5, 0, 0), -1, -1));
        rootComponent.add(panel1, BorderLayout.CENTER);
        panel1.add(comboBox, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        btnRun = new JButton();
        btnRun.setText("Run");
        btnRun.setToolTipText("Click Run to execute the selected entry [ENTER]");
        panel1.add(btnRun, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        panel1.add(panel2, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        lblHistoryPrev = new JLabel();
        lblHistoryPrev.setText("");
        lblHistoryPrev.setToolTipText("Click to select the previous entry in history [CTRL+SHIFT+TAB]");
        panel2.add(lblHistoryPrev, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        lblHistoryNext = new JLabel();
        lblHistoryNext.setText("");
        lblHistoryNext.setToolTipText("Click to select the next entry in history [CTRL+TAB]");
        panel2.add(lblHistoryNext, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return rootComponent;
    }

    protected void createUIComponents() {
        comboBox = new FilterComboBox<>();
    }
}
