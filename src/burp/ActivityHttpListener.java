package burp;

import java.util.Locale;

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
            //Save the information of the current request if the message is an HTTP request and according to the restriction options
            if (messageIsRequest) {
                IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(messageInfo);
                if (this.mustLogRequest(reqInfo)) {
                    this.activityLogger.logEvent(toolFlag, reqInfo, messageInfo.getRequest());
                }
            }
        } catch (Exception e) {
            this.trace.writeLog("Cannot save request: " + e.getMessage());
        }
    }

    /**
     * Determine if the current request must be logged according to the configuration options selected by the users.
     *
     * @param reqInfo Information about the current request
     * @return TRUE if the request must be logged, FALSE otherwise
     */
    private boolean mustLogRequest(IRequestInfo reqInfo) {
        //By default: Request is logged
        boolean mustLogRequest = true;

        //Initially we check the pause state
        if (ConfigMenu.IS_LOGGING_PAUSED) {
            mustLogRequest = false;
        } else {
            //First: We check if we must apply restriction about image resource
            if (ConfigMenu.EXCLUDE_IMAGE_RESOURCE_REQUESTS) {
                //Get the file extension of the current URL and remove the parameters from the URL
                String filename = reqInfo.getUrl().getFile();
                if (filename != null && filename.indexOf('?') != -1) {
                    filename = filename.substring(0, filename.indexOf('?')).trim();
                }
                if (filename != null && filename.indexOf('#') != -1) {
                    filename = filename.substring(0, filename.indexOf('#')).trim();
                }
                if (filename != null && filename.lastIndexOf('.') != -1) {
                    String extension = filename.substring(filename.lastIndexOf('.') + 1).trim().toLowerCase(Locale.US);
                    if (ConfigMenu.IMAGE_RESOURCE_EXTENSIONS.contains(extension)) {
                        mustLogRequest = false;
                    }
                }
            }
            //Secondly: We check if we must apply restriction about the URL scope
            //Configuration restrictions options are applied in sequence so we only work here if the request is marked to be logged
            if (mustLogRequest && ConfigMenu.ONLY_INCLUDE_REQUESTS_FROM_SCOPE && !this.callbacks.isInScope(reqInfo.getUrl())) {
                mustLogRequest = false;
            }
        }

        return mustLogRequest;

    }
}
