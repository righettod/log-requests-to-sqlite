package burp;

import javax.swing.JFileChooser;
import javax.swing.JFrame;
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
        JFrame burpFrame = ConfigMenu.getBurpFrame();
        try {
            //Extension init.
            callbacks.setExtensionName(extensionName);
            Trace trace = new Trace(callbacks);
            //Ask to the user if he want to continue to log the events in the current DB file
            String defaultStoreFileName = new File(System.getProperty("user.home"), extensionName + ".db").getAbsolutePath().replaceAll("\\\\", "/");
            String customStoreFileName = callbacks.loadExtensionSetting(ConfigMenu.DB_FILE_CUSTOM_LOCATION_CFG_KEY);
            if (customStoreFileName == null) {
                customStoreFileName = defaultStoreFileName;
            }
            int loggingQuestionReply = JOptionPane.showConfirmDialog(burpFrame, "Continue to log events into the following database file?\n\r" + customStoreFileName, extensionName, JOptionPane.YES_NO_OPTION);
            if (loggingQuestionReply == JOptionPane.NO_OPTION) {
                JFileChooser customStoreFileNameFileChooser = new JFileChooser();
                customStoreFileNameFileChooser.setDialogTitle(extensionName + " - Select the DB file to use...");
                customStoreFileNameFileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
                customStoreFileNameFileChooser.setDialogType(JFileChooser.SAVE_DIALOG);
                customStoreFileNameFileChooser.setDragEnabled(false);
                customStoreFileNameFileChooser.setMultiSelectionEnabled(false);
                customStoreFileNameFileChooser.setAcceptAllFileFilterUsed(false);
                customStoreFileNameFileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                customStoreFileNameFileChooser.setFileHidingEnabled(true);
                int dbFileSelectionReply = customStoreFileNameFileChooser.showDialog(burpFrame, "Use");
                if (dbFileSelectionReply == JFileChooser.APPROVE_OPTION) {
                    customStoreFileName = customStoreFileNameFileChooser.getSelectedFile().getAbsolutePath().replaceAll("\\\\", "/");
                } else {
                    JOptionPane.showMessageDialog(burpFrame, "The following database file will continue to be used:\n\r" + customStoreFileName, extensionName, JOptionPane.INFORMATION_MESSAGE);
                }
            }
            //Save the location of the database file chosen by the user
            callbacks.saveExtensionSetting(ConfigMenu.DB_FILE_CUSTOM_LOCATION_CFG_KEY, customStoreFileName);
            //Init logger and HTTP listener
            ActivityLogger activityLogger = new ActivityLogger(customStoreFileName, callbacks, trace);
            ActivityHttpListener activityHttpListener = new ActivityHttpListener(activityLogger, trace, callbacks);
            //Setup the configuration menu
            configMenu = new ConfigMenu(callbacks, trace, activityLogger);
            SwingUtilities.invokeLater(configMenu);
            //Register all listeners
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
            JOptionPane.showMessageDialog(burpFrame, errMsg, extensionName, JOptionPane.ERROR_MESSAGE);
        }
    }
}
