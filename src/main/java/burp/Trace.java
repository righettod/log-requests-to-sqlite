package burp;

import burp.api.montoya.MontoyaApi;

/**
 * Write a log into the BURP ALERT TAB.
 */
class Trace {

    /**
     * The MontoyaAPI object used for accessing all the Burp features and ressources such as requests and responses.
     */
    private final MontoyaApi api;


    /**
     * Constructor.
     *
     * @param api The MontoyaAPI object used for accessing all the Burp features and ressources such as requests and responses.
     */
    Trace(MontoyaApi api) {
        this.api = api;
    }


    /**
     * Write log
     *
     * @param message Message to write.
     */
    void writeLog(String message) {
        this.api.logging().logToOutput(message);
    }

}
