package burp;

import com.google.common.collect.Lists;
import net.bytebutcher.burp.quicker.context.gui.crawler.ApplicationMenuCrawler;
import net.bytebutcher.burp.quicker.context.gui.crawler.ContextMenuCrawler;
import net.bytebutcher.burp.quicker.context.gui.crawler.TabsCrawler;
import net.bytebutcher.burp.quicker.context.gui.keystroke.KeyStrokeListener;
import net.bytebutcher.burp.quicker.context.gui.keystroke.KeyStrokeManager;
import net.bytebutcher.burp.quicker.context.gui.widget.dialog.QuickerContextDialog;
import net.bytebutcher.burp.quicker.context.gui.widget.tab.QuickerContextTab;
import net.bytebutcher.burp.quicker.context.model.Config;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.util.List;

public class BurpExtender implements IBurpExtender, ITab, IExtensionStateListener {

    private static final String extensionName = "Quicker Context";

    private IBurpExtenderCallbacks callbacks;
    private static PrintWriter stdout;
    private static PrintWriter stderr;
    public static BurpExtender instance = null;

    private JPanel panel = new JPanel();
    private Container parent;
    private Config config;

    private KeyStrokeManager keyStrokeManager;
    private boolean isQuickerContextDialogVisible;
    private QuickerContextTab quickerContextTab;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        instance = this;
        this.callbacks = callbacks;
        initLogHandler(callbacks);
        stdout.println("Initializing Quicker Context Extension...");
        this.callbacks.setExtensionName(BurpExtender.extensionName);
        stdout.println("Loading config...");
        this.config = new Config(this);
        stdout.println("Initializing state listener...");
        callbacks.registerExtensionStateListener(this);
        stdout.println("Initializing key stroke manager...");
        initKeyStrokeManager();
        stdout.println("Initializing tab...");
        this.quickerContextTab = new QuickerContextTab(keyStrokeManager);
        SwingUtilities.invokeLater(() -> {
            callbacks.addSuiteTab(this);
            parent = SwingUtilities.getRootPane(getUiComponent()).getParent();
            stdout.println("Initializing context menu entry...");
            initContextMenuEntry();
        });
    }

    private void initLogHandler(IBurpExtenderCallbacks callbacks) {
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
    }

    private void initContextMenuEntry() {
        JTabbedPane tabbedPane = (JTabbedPane) this.getUiComponent().getParent();
        JRootPane rootPane = SwingUtilities.getRootPane(tabbedPane);
        SwingUtilities.invokeLater(() -> {
            callbacks.registerContextMenuFactory(new IContextMenuFactory() {
                @Override
                public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
                    JMenuItem quickerContextMenu = new JMenuItem();
                    quickerContextMenu.setAction(new AbstractAction("Quicker...") {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            new QuickerContextDialog(BurpExtender.this, Lists.newArrayList(new ContextMenuCrawler(quickerContextMenu.getParent()), new TabsCrawler(tabbedPane), new ApplicationMenuCrawler(rootPane.getJMenuBar())));
                        }

                    });
                    return Lists.newArrayList(quickerContextMenu);
                }
            });
        });
    }

    private void initKeyStrokeManager() {
        this.keyStrokeManager = new KeyStrokeManager(callbacks);
        this.keyStrokeManager.push(new KeyStrokeListener() {
            @Override
            public void dispatchKeyStroke(KeyStroke keyStroke) {
                try {
                    if (!isQuickerContextDialogVisible) {
                        KeyStroke quickerKeyBinding = keyStrokeManager.getKeyBinding();
                        if (quickerKeyBinding != null) {
                            if (quickerKeyBinding.equals(keyStroke)) {
                                JTabbedPane tabbedPane = (JTabbedPane) BurpExtender.this.getUiComponent().getParent();
                                JRootPane rootPane = SwingUtilities.getRootPane(tabbedPane);
                                isQuickerContextDialogVisible = true;
                                new QuickerContextDialog(BurpExtender.this, Lists.newArrayList(new TabsCrawler(tabbedPane), new ApplicationMenuCrawler(rootPane.getJMenuBar())));
                                isQuickerContextDialogVisible = false;
                            }
                        }
                    }
                } catch (RuntimeException e) {
                    isQuickerContextDialogVisible = false;
                }
            }
        });
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return this.callbacks;
    }

    public static void printOut(String s) {
        stdout.println(s);
    }

    public static void printErr(String s) {
        stderr.println(s);
    }

    public Container getParent() {
        return parent;
    }

    @Override
    public String getTabCaption() {
        return "Quicker Context";
    }

    @Override
    public Component getUiComponent() {
        return quickerContextTab.getRootPanel();
    }

    public Config getConfig() {
        return config;
    }

    @Override
    public void extensionUnloaded() {
        printOut("Unloading Quicker Context Extension...");
        this.keyStrokeManager.unload();
    }
}
