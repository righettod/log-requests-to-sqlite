package burp;

import java.io.File;

/**
 * Entry point of the extension
 */
public class BurpExtender implements IBurpExtender {

    /**
     * {@inheritDoc}
     */
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        try {
            String extensionName = "ActivityTrailLog";
            callbacks.setExtensionName(extensionName);
            Trace trace = new Trace(callbacks);
            String storeFileName = new File(System.getProperty("user.home"),extensionName + ".db").getAbsolutePath().replaceAll("\\\\","/");
            ActivityLogger activityLogger = new ActivityLogger(storeFileName, callbacks, trace);
            ActivityHttpListener activityHttpListener = new ActivityHttpListener(activityLogger, trace);
            callbacks.registerHttpListener(activityHttpListener);
            callbacks.registerExtensionStateListener(activityLogger);
        } catch (Exception e) {
            callbacks.issueAlert("Cannot start the extension: " + e.getMessage());
        }
    }
}
