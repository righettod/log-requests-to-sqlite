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
            //If the logging is not paused then ask to the user if he want to continue to log the events in the current DB file or pause the logging
            String defaultStoreFileName = new File(System.getProperty("user.home"), extensionName + ".db").getAbsolutePath().replaceAll("\\\\", "/");
            String customStoreFileName = callbacks.loadExtensionSetting(ConfigMenu.DB_FILE_CUSTOM_LOCATION_CFG_KEY);
            if (customStoreFileName == null) {
                customStoreFileName = defaultStoreFileName;
            }
            boolean isLoggingPaused = Boolean.parseBoolean(callbacks.loadExtensionSetting(ConfigMenu.PAUSE_LOGGING_CFG_KEY));
            if (!isLoggingPaused) {
                Object[] options = {"Keep the DB file", "Change the DB file", "Pause the logging"};
                String msg = "Continue to log events into the following database file?\n\r" + customStoreFileName;
                //Mapping of the buttons with the dialog: options[0] => YES / options[1] => NO / options[2] => CANCEL
                int loggingQuestionReply = JOptionPane.showOptionDialog(burpFrame, msg, extensionName, JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, null);
                //Case for YES is already handled, use the stored file
                if (loggingQuestionReply == JOptionPane.YES_OPTION) {
                    callbacks.saveExtensionSetting(ConfigMenu.PAUSE_LOGGING_CFG_KEY, Boolean.FALSE.toString());
                    callbacks.issueAlert("Logging is enabled.");
                }
                //Case for the NO => Change DB file
                if (loggingQuestionReply == JOptionPane.NO_OPTION) {
                    JFileChooser customStoreFileNameFileChooser = Utilities.createDBFileChooser();
                    int dbFileSelectionReply = customStoreFileNameFileChooser.showDialog(burpFrame, "Use");
                    if (dbFileSelectionReply == JFileChooser.APPROVE_OPTION) {
                        customStoreFileName = customStoreFileNameFileChooser.getSelectedFile().getAbsolutePath().replaceAll("\\\\", "/");
                    } else {
                        JOptionPane.showMessageDialog(burpFrame, "The following database file will continue to be used:\n\r" + customStoreFileName, extensionName, JOptionPane.INFORMATION_MESSAGE);
                    }
                    callbacks.saveExtensionSetting(ConfigMenu.PAUSE_LOGGING_CFG_KEY, Boolean.FALSE.toString());
                    callbacks.issueAlert("Logging is enabled.");
                }
                //Case for the CANCEL => Pause the logging
                if (loggingQuestionReply == JOptionPane.CANCEL_OPTION) {
                    callbacks.saveExtensionSetting(ConfigMenu.PAUSE_LOGGING_CFG_KEY, Boolean.TRUE.toString());
                    callbacks.issueAlert("Logging is paused.");
                }
                //Save the location of the database file chosen by the user
                callbacks.saveExtensionSetting(ConfigMenu.DB_FILE_CUSTOM_LOCATION_CFG_KEY, customStoreFileName);
            } else {
                callbacks.issueAlert("Logging is paused.");
            }
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
