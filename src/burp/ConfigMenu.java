package burp;

import javax.swing.AbstractAction;
import javax.swing.JCheckBoxMenuItem;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import java.awt.Frame;
import java.awt.event.ActionEvent;

/**
 * Menu to configure the extension options. Currently, there only a single option that allow to restrict the logging to defined target scope.
 */
class ConfigMenu implements Runnable, IExtensionStateListener {

    /**
     * Expose the single configuration option to the extension classes.
     */
    static volatile boolean ONLY_INCLUDE_REQUESTS_FROM_SCOPE = Boolean.FALSE;

    /**
     * Option configuration key.
     */
    private static final String CFG_KEY = "ONLY_INCLUDE_REQUESTS_FROM_SCOPE";

    /**
     * Extension root configuration menu.
     */
    private JMenu cfgMenu;

    /**
     * Ref on Burp tool to manipulate the HTTP requests and have access to API to identify the source of the activity (tool name).
     */
    private IBurpExtenderCallbacks callbacks;

    /**
     * Ref on project logger.
     */
    private Trace trace;


    /**
     * Constructor.
     *
     * @param callbacks Ref on Burp tool to manipulate the HTTP requests and have access to API to identify the source of the activity (tool name).
     * @param trace     Ref on project logger.
     */
    ConfigMenu(IBurpExtenderCallbacks callbacks, Trace trace) {
        this.callbacks = callbacks;
        this.trace = trace;
        //Load the save state of the options
        String value = this.callbacks.loadExtensionSetting(CFG_KEY);
        if (value != null) {
            ONLY_INCLUDE_REQUESTS_FROM_SCOPE = Boolean.parseBoolean(value);
        }
    }

    /**
     * Build the options menu used to configure the extension.
     */
    @Override
    public void run() {
        //Build the menu
        String menuText = "Log only requests from defined target scope";
        this.cfgMenu = new JMenu("Audit Trail");
        final JCheckBoxMenuItem scopeMenuItem = new JCheckBoxMenuItem(menuText, ONLY_INCLUDE_REQUESTS_FROM_SCOPE);
        scopeMenuItem.addActionListener(new AbstractAction(menuText) {
            public void actionPerformed(ActionEvent e) {
                if (scopeMenuItem.isSelected()) {
                    ConfigMenu.this.callbacks.saveExtensionSetting(CFG_KEY, Boolean.TRUE.toString());
                    ConfigMenu.this.ONLY_INCLUDE_REQUESTS_FROM_SCOPE = Boolean.TRUE;
                    ConfigMenu.this.trace.writeLog("From now, only requests from defined target scope will be logged.");
                } else {
                    ConfigMenu.this.callbacks.saveExtensionSetting(CFG_KEY, Boolean.FALSE.toString());
                    ConfigMenu.this.ONLY_INCLUDE_REQUESTS_FROM_SCOPE = Boolean.FALSE;
                    ConfigMenu.this.trace.writeLog("From now, all requests will be logged.");
                }
            }
        });
        this.cfgMenu.add(scopeMenuItem);
        //Add it to BURP menu
        JFrame burpFrame = ConfigMenu.getBurpFrame();
        if (burpFrame != null) {
            JMenuBar jMenuBar = burpFrame.getJMenuBar();
            jMenuBar.add(this.cfgMenu);
            jMenuBar.repaint();
            this.trace.writeLog("Configuration menu added.");
        } else {
            this.trace.writeLog("Cannot add the configuration menu (ref on the BURP frame is null).");
        }
    }

    /**
     * Remove the menu from BURP menu bar.
     *
     * @see "https://github.com/PortSwigger/param-miner/blob/master/src/burp/Utilities.java"
     */
    @Override
    public void extensionUnloaded() {
        JFrame burpFrame = ConfigMenu.getBurpFrame();
        if (burpFrame != null && this.cfgMenu != null) {
            JMenuBar jMenuBar = burpFrame.getJMenuBar();
            jMenuBar.remove(this.cfgMenu);
            jMenuBar.repaint();
            this.trace.writeLog("Configuration menu removed.");
        } else {
            this.trace.writeLog("Cannot remove the configuration menu (ref on the BURP frame is null).");
        }
    }

    /**
     * Get a reference on the BURP main frame.
     *
     * @return BURP main frame.
     * @see "https://github.com/PortSwigger/param-miner/blob/master/src/burp/Utilities.java"
     */
    private static JFrame getBurpFrame() {
        for (Frame f : Frame.getFrames()) {
            if (f.isVisible() && f.getTitle().startsWith(("Burp Suite"))) {
                return (JFrame) f;
            }
        }
        return null;
    }
}
