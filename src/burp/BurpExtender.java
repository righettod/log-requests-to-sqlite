package burp;

import javax.swing.SwingUtilities;
import java.io.File;

/**
 * Entry point of the extension
 */
public class BurpExtender implements IBurpExtender {

    /**
     * {@inheritDoc}
     */
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        ConfigMenu configMenu = null;
        try {
            String extensionName = "LogRequestsToSQLite";
            callbacks.setExtensionName(extensionName);
            Trace trace = new Trace(callbacks);
            configMenu = new ConfigMenu(callbacks, trace);
            SwingUtilities.invokeLater(configMenu);
            String storeFileName = new File(System.getProperty("user.home"), extensionName + ".db").getAbsolutePath().replaceAll("\\\\", "/");
            ActivityLogger activityLogger = new ActivityLogger(storeFileName, callbacks, trace);
            ActivityHttpListener activityHttpListener = new ActivityHttpListener(activityLogger, trace, callbacks);
            callbacks.registerHttpListener(activityHttpListener);
            callbacks.registerExtensionStateListener(activityLogger);
            callbacks.registerExtensionStateListener(configMenu);
        } catch (Exception e) {
            callbacks.issueAlert("Cannot start the extension: " + e.getMessage());
            //Unload the menu if the extension cannot be loaded
            if (configMenu != null) {
                configMenu.extensionUnloaded();
            }
        }
    }
}
