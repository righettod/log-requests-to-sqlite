package burp;

/**
 * Handle the recording of HTTP activities into the activity log storage.
 */
class ActivityHttpListener implements IHttpListener {

    /**
     * Ref on handler that will store the activity information into the activity log storage.
     */
    private ActivityLogger activityLogger;

    /**
     * Ref on project logger.
     */
    private Trace trace;

    /**
     * Constructor.
     *
     * @param activityLogger Ref on handler that will store the activity information into the activity log storage.
     * @param trace          Ref on project logger.
     */
    ActivityHttpListener(ActivityLogger activityLogger, Trace trace) {
        this.activityLogger = activityLogger;
        this.trace = trace;
    }

    /**
     * {@inheritDoc}
     */
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        try {
            //Save the information of the current request if the message is an HTTP request
            if (messageIsRequest) {
                this.activityLogger.logEvent(toolFlag, messageInfo);
            }
        } catch (Exception e) {
            this.trace.writeLog("Cannot save request: " + e.getMessage());
        }
    }
}
