package burp;

/**
 * Write a log into the BURP ALERT TAB.
 */
class Trace {

    /**
     * Ref on Burp tool to have access to the BURP ALERT TAB.
     */
    private final IBurpExtenderCallbacks callbacks;


    /**
     * Constructor.
     *
     * @param callbacks Ref on Burp tool to have access tot he BURP ALERT TAB.
     */
    Trace(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }


    /**
     * Write log
     *
     * @param message Message to write.
     */
    void writeLog(String message) {
        this.callbacks.issueAlert(message);
    }

}
