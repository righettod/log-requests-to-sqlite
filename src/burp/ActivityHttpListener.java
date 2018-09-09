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
     * Ref on Burp tool to manipulate the HTTP requests and have access to API to identify the source of the activity (tool name).
     */
    private IBurpExtenderCallbacks callbacks;

    /**
     * Constructor.
     *
     * @param activityLogger Ref on handler that will store the activity information into the activity log storage.
     * @param trace          Ref on project logger.
     * @param callbacks      Ref on Burp tool to manipulate the HTTP requests and have access to API to identify the source of the activity (tool name).
     */
    ActivityHttpListener(ActivityLogger activityLogger, Trace trace, IBurpExtenderCallbacks callbacks) {
        this.activityLogger = activityLogger;
        this.trace = trace;
        this.callbacks = callbacks;
    }

    /**
     * {@inheritDoc}
     */
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        try {
            //Save the information of the current request if the message is an HTTP request and according to the scope restriction option
            if (messageIsRequest) {
                boolean mustLogRequest = false;
                IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(messageInfo);
                if (!ConfigMenu.ONLY_INCLUDE_REQUESTS_FROM_SCOPE) {
                    mustLogRequest = true;
                } else if (this.callbacks.isInScope(reqInfo.getUrl())) {
                    mustLogRequest = true;
                }

                //Log the request if the condition are meet
                if (mustLogRequest) {
                    this.activityLogger.logEvent(toolFlag, reqInfo, messageInfo.getRequest());
                }
            }
        } catch (Exception e) {
            this.trace.writeLog("Cannot save request: " + e.getMessage());
        }
    }
}
