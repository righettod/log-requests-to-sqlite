package burp;

import javax.swing.JOptionPane;
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
        String extensionName = "LogRequestsToSQLite";
        try {
            callbacks.setExtensionName(extensionName);
            Trace trace = new Trace(callbacks);
            String storeFileName = new File(System.getProperty("user.home"), extensionName + ".db").getAbsolutePath().replaceAll("\\\\", "/");
            ActivityLogger activityLogger = new ActivityLogger(storeFileName, callbacks, trace);
            ActivityHttpListener activityHttpListener = new ActivityHttpListener(activityLogger, trace, callbacks);
            configMenu = new ConfigMenu(callbacks, trace, activityLogger);
            SwingUtilities.invokeLater(configMenu);
            callbacks.registerHttpListener(activityHttpListener);
            callbacks.registerExtensionStateListener(activityLogger);
            callbacks.registerExtensionStateListener(configMenu);
        } catch (Exception e) {
            String errMsg = "Cannot start the extension due to the following reason:\n\r" + e.getMessage();
            //Unload the menu if the extension cannot be loaded
            if (configMenu != null) {
                configMenu.extensionUnloaded();
            }
            //Notification of the error in the dashboard tab
            callbacks.issueAlert(errMsg);
            //Notification of the error using the UI
            JOptionPane.showMessageDialog(ConfigMenu.getBurpFrame(), errMsg, extensionName, JOptionPane.ERROR_MESSAGE);
        }
    }
}
