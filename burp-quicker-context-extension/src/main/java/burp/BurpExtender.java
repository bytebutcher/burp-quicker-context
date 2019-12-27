package burp;

import com.google.common.collect.Lists;
import net.bytebutcher.burp.quicker.context.gui.crawler.ContextMenuCrawler;
import net.bytebutcher.burp.quicker.context.gui.model.ContextMenuEvent;
import net.bytebutcher.burp.quicker.context.gui.widget.dialog.QuickerContextDialog;
import net.bytebutcher.burp.quicker.context.model.Config;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.util.List;

public class BurpExtender implements IBurpExtender, ITab {

    private static final String extensionName = "Quicker Context";

    private IBurpExtenderCallbacks callbacks;
    private static PrintWriter stdout;
    private static PrintWriter stderr;
    public static BurpExtender instance = null;

    private JPanel panel = new JPanel();
    private Container parent;
    private Config config;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        instance = this;
        this.callbacks = callbacks;
        initLogHandler(callbacks);
        stdout.println("Initializing Quicker Context Extension...");
        this.callbacks.setExtensionName(BurpExtender.extensionName);
        stdout.println("Loading config...");
        this.config = new Config(this);
        stdout.println("Initializing context menu entry...");
        initContextMenuEntry();
    }

    private void initLogHandler(IBurpExtenderCallbacks callbacks) {
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
    }

    private void initContextMenuEntry() {
        callbacks.registerContextMenuFactory(new IContextMenuFactory() {
            @Override
            public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
                JMenuItem quickerContextMenu = new JMenuItem();
                quickerContextMenu.setAction(new AbstractAction("Quicker...") {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        getQuickerContextDialog(new ContextMenuEvent(quickerContextMenu.getParent(), e));
                    }

                });
                return Lists.newArrayList(quickerContextMenu);
            }
        });
    }

    private QuickerContextDialog getQuickerContextDialog(ContextMenuEvent contextMenuEvent) {
        return new QuickerContextDialog(this, contextMenuEvent);
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
        if (parent == null) {
            callbacks.addSuiteTab(this);
            parent = SwingUtilities.getRootPane(getUiComponent()).getParent();
            callbacks.removeSuiteTab(this);
        }
        return parent;
    }

    @Override
    public String getTabCaption() {
        return "Quicker Context";
    }

    @Override
    public Component getUiComponent() {
        return panel;
    }

    public Config getConfig() {
        return config;
    }
}
