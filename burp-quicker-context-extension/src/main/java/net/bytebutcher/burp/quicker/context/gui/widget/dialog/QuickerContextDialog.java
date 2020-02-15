package net.bytebutcher.burp.quicker.context.gui.widget.dialog;

import burp.BurpExtender;
import com.google.common.collect.EvictingQueue;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import net.bytebutcher.burp.quicker.context.gui.crawler.ICrawler;
import net.bytebutcher.burp.util.DialogUtil;
import net.bytebutcher.burp.quicker.context.gui.widget.combobox.FilterComboBox;
import net.bytebutcher.burp.quicker.context.model.History;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.HashSet;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.List;

public class QuickerContextDialog extends JDialog {
    protected final BurpExtender burpExtender;
    public JPanel rootComponent;
    protected JComboBox<String> cmbSearch;
    private JButton btnRun;
    private JButton btnHistoryNext;
    private JButton btnHistoryPrev;
    private Map<String, JMenuItem> contextMenuEntries;
    private History history;

    private final List<ICrawler> crawlers;

    public QuickerContextDialog(BurpExtender burpExtender, List<ICrawler> crawlers) {
        this.burpExtender = burpExtender;
        this.crawlers = crawlers;
        $$$setupUI$$$();
        this.setLayout(new BorderLayout());
        this.setContentPane(rootComponent);
        btnRun.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                execute(new ActionEvent(e.getSource(), e.getID(), e.paramString()));
                dispose();
            }
        });
        setupHistory();
        registerKeyBoardAction();
        initializeComboBox();
        requestFocus();
        setSize(250, 50);
        pack();
        setIconImages(((Window) burpExtender.getParent()).getIconImages());
        setModal(true);
        setTitle("Quicker Context");
        setLocation(DialogUtil.getX(burpExtender.getParent(), this), DialogUtil.getY(burpExtender.getParent(), this));
        setVisible(true);
    }

    private void registerKeyBoardAction() {
        cmbSearch.getEditor().getEditorComponent().addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                switch (e.getKeyCode()) {
                    case KeyEvent.VK_ENTER:
                        execute(new ActionEvent(e.getSource(), e.getID(), e.paramString()));
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
                execute(e);
                dispose();
            }
        }, KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), JComponent.WHEN_IN_FOCUSED_WINDOW);
        rootComponent.registerKeyboardAction(e -> dispose(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_IN_FOCUSED_WINDOW);
    }

    protected void setupHistory() {
        history = new History(getContextMenuEntries().keySet(), burpExtender);
        JTextField textField = (JTextField) cmbSearch.getEditor().getEditorComponent();
        setupHistoryTraversalKeys(textField, history, burpExtender);
        setupHistoryButtons(textField);
    }

    private void setupHistoryButtons(JTextField textField) {
        this.btnHistoryPrev.setEnabled(!history.isEmpty());
        this.btnHistoryPrev.setText("<");
        this.btnHistoryPrev.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (!history.isEmpty()) {
                    textField.setText(history.previous().toString());
                }
            }
        });
        this.btnHistoryNext.setEnabled(!history.isEmpty());
        this.btnHistoryNext.setText(">");
        this.btnHistoryNext.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (!history.isEmpty()) {
                    textField.setText(history.next().toString());
                }
            }
        });
    }

    public void initializeComboBox() {
        Set<String> contextMenuEntries = getContextMenuEntries().keySet();
        for (String tabCaption : contextMenuEntries) {
            cmbSearch.addItem(tabCaption);
        }
        if (!history.isEmpty()) {
            SwingUtilities.invokeLater(() -> ((JTextField) cmbSearch.getEditor().getEditorComponent()).setText(history.toString()));
        }
        SwingUtilities.invokeLater(() -> cmbSearch.getEditor().selectAll());
    }

    private Map<String, JMenuItem> getContextMenuEntries() {
        if (contextMenuEntries == null) {
            contextMenuEntries = Maps.newHashMap();
            for (ICrawler crawler : crawlers) {
                contextMenuEntries.putAll(crawler.getContextMenuEntries());
            }
        }
        return contextMenuEntries;
    }

    private void saveToHistory(String selectedItem) {
        Queue<String> history = EvictingQueue.create(20);
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
                            textField.setText(history.next().toString());
                        }
                    }
                });
        inputMap.put(ctrlShiftTab, "navigatePrevious");
        textField.getActionMap().put("navigatePrevious",
                new AbstractAction() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        if (!history.isEmpty()) {
                            textField.setText(history.next().toString());
                        }
                    }
                });
    }

    public String getSelectedItem() {
        return cmbSearch.getItemAt(cmbSearch.getSelectedIndex());
    }

    public void execute(ActionEvent e) {
        saveToHistory(getSelectedItem());
        JMenuItem selectedMenuItem = getContextMenuEntries().get(getSelectedItem());
        if (selectedMenuItem != null) {
            for (ActionListener actionListener : selectedMenuItem.getActionListeners()) {
                actionListener.actionPerformed(e);
            }
        }
    }

    public void requestFocus() {
        cmbSearch.requestFocus();
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
        panel1.setLayout(new GridLayoutManager(1, 4, new Insets(0, 0, 0, 0), 0, 0));
        rootComponent.add(panel1, BorderLayout.CENTER);
        panel1.add(cmbSearch, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        btnRun = new JButton();
        btnRun.setText("Run");
        btnRun.setToolTipText("Click Run to execute the selected entry [ENTER]");
        panel1.add(btnRun, new GridConstraints(0, 3, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        btnHistoryNext = new JButton();
        btnHistoryNext.setText(">");
        btnHistoryNext.setToolTipText("Click to select the next entry in history [CTRL+TAB]");
        panel1.add(btnHistoryNext, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        btnHistoryPrev = new JButton();
        btnHistoryPrev.setText("<");
        btnHistoryPrev.setToolTipText("Click to select the previous entry in history [CTRL+SHIFT+TAB]");
        panel1.add(btnHistoryPrev, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return rootComponent;
    }

    protected void createUIComponents() {
        cmbSearch = new FilterComboBox<>();
    }
}
