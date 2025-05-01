package burp;

import java.net.InetAddress;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.extension.ExtensionUnloadingHandler;

/**
 * Handle the recording of the activities into the real storage, SQLite local DB here.
 */
class ActivityLogger implements ExtensionUnloadingHandler {

    /**
     * SQL instructions.
     */
    private static final String SQL_TABLE_CREATE = "CREATE TABLE IF NOT EXISTS ACTIVITY (LOCAL_SOURCE_IP TEXT, TARGET_URL TEXT, HTTP_METHOD TEXT, BURP_TOOL TEXT, REQUEST_RAW TEXT, SEND_DATETIME TEXT, HTTP_STATUS_CODE TEXT, RESPONSE_RAW TEXT)";
    private static final String SQL_TABLE_INSERT = "INSERT INTO ACTIVITY (LOCAL_SOURCE_IP,TARGET_URL,HTTP_METHOD,BURP_TOOL,REQUEST_RAW,SEND_DATETIME,HTTP_STATUS_CODE,RESPONSE_RAW) VALUES(?,?,?,?,?,?,?,?)";
    private static final String SQL_COUNT_RECORDS = "SELECT COUNT(HTTP_METHOD) FROM ACTIVITY";
    private static final String SQL_TOTAL_AMOUNT_DATA_SENT = "SELECT TOTAL(LENGTH(REQUEST_RAW)) FROM ACTIVITY";
    private static final String SQL_BIGGEST_REQUEST_AMOUNT_DATA_SENT = "SELECT MAX(LENGTH(REQUEST_RAW)) FROM ACTIVITY";
    private static final String SQL_MAX_HITS_BY_SECOND = "SELECT COUNT(REQUEST_RAW) AS HITS, SEND_DATETIME FROM ACTIVITY GROUP BY SEND_DATETIME ORDER BY HITS DESC";

    /**
     * Empty string to use when response must be not be logged.
     */
    private static final String EMPTY_RESPONSE_CONTENT = "";


    /**
     * Use a single DB connection for performance and to prevent DB file locking issue at filesystem level.
     */
    private Connection storageConnection;

    /**
     * DB URL
     */
    private String url;

    /**
     * The MontoyaAPI object used for accessing all the Burp features and ressources such as requests and responses.
     */
    private MontoyaApi api;

    /**
     * Ref on project logger.
     */
    private Trace trace;

    /**
     * Formatter for date/time.
     */
    private DateTimeFormatter datetimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");


    /**
     * Constructor.
     *
     * @param storeName     Name of the storage that will be created (file path).
     * @param api           The MontoyaAPI object used for accessing all the Burp features and ressources such as requests and responses.
     * @param trace         Ref on project logger.
     * @throws Exception    If connection with the DB cannot be opened or if the DB cannot be created or if the JDBC driver cannot be loaded.
     */
    ActivityLogger(String storeName, MontoyaApi api, Trace trace) throws Exception {
        //Load the SQLite driver
        Class.forName("org.sqlite.JDBC");
        //Affect the properties
        this.api = api;
        this.trace = trace;
        updateStoreLocation(storeName);
    }

    /**
     * Change the location where DB is stored.
     *
     * @param storeName Name of the storage that will be created (file path).
     * @throws Exception If connection with the DB cannot be opened or if the DB cannot be created or if the JDBC driver cannot be loaded.
     */
    void updateStoreLocation(String storeName) throws Exception {
        String newUrl = "jdbc:sqlite:" + storeName;
        this.url = newUrl;
        //Open the connection to the DB
        this.trace.writeLog("Activity information will be stored in database file '" + storeName + "'.");
        this.storageConnection = DriverManager.getConnection(newUrl);
        this.storageConnection.setAutoCommit(true);
        this.trace.writeLog("Open new connection to the storage.");
        //Create the table
        try (Statement stmt = this.storageConnection.createStatement()) {
            stmt.execute(SQL_TABLE_CREATE);
            this.trace.writeLog("Recording table initialized.");
        }
    }

    /**
     * Save an activity event into the storage.
     *
     * @param request       HttpRequest object containing all information about the request
     *                      which was either sent or will be sent out soon.
     * @param response      HttpResponse object containing all information about the response.
     *                      Is null when only the request ist stored.
     * @param tool          The name of the tool which was used to issue to request.
     * @throws Exception    If event cannot be saved.
     */
    void logEvent(HttpRequest request, HttpResponse response, String tool) throws Exception {
        //Verify that the DB connection is still opened
        this.ensureDBState();
        //Insert the event into the storage
        try (PreparedStatement stmt = this.storageConnection.prepareStatement(SQL_TABLE_INSERT)) {
            stmt.setString(1, InetAddress.getLocalHost().getHostAddress());
            stmt.setString(2, request.url());
            stmt.setString(3, request.method());
            stmt.setString(4, tool);
            stmt.setString(5, request.toString()); //Apparently, bodyToString() does not work..
            stmt.setString(6, LocalDateTime.now().format(this.datetimeFormatter));
            //Make a distinction if only the request is stored or the response is added as well.
            if (response != null) {
                stmt.setString(7, String.valueOf(response.statusCode()));
                stmt.setString(8, response.bodyToString());
            } else {
                stmt.setString(7, null);
                stmt.setString(8, null);
            }
            int count = stmt.executeUpdate();
            if (count != 1) {
                this.trace.writeLog("Request was not inserted, no detail available (insertion counter = " + count + ") !");
            }
        }
    }

    /**
     * Extract and compute statistics about the DB.
     *
     * @return A VO object containing the statistics.
     * @throws Exception If computation meet and error.
     */
    DBStats getEventsStats() throws Exception {
        //Verify that the DB connection is still opened
        this.ensureDBState();
        //Get the total of the records in the activity table
        long recordsCount;
        try (PreparedStatement stmt = this.storageConnection.prepareStatement(SQL_COUNT_RECORDS)) {
            try (ResultSet rst = stmt.executeQuery()) {
                recordsCount = rst.getLong(1);
            }
        }
        //Get data amount if the DB is not empty
        long totalAmountDataSent = 0;
        long biggestRequestAmountDataSent = 0;
        long maxHitsBySecond = 0;
        if (recordsCount > 0) {
            //Get the total amount of data sent, we assume here that 1 character = 1 byte
            try (PreparedStatement stmt = this.storageConnection.prepareStatement(SQL_TOTAL_AMOUNT_DATA_SENT)) {
                try (ResultSet rst = stmt.executeQuery()) {
                    totalAmountDataSent = rst.getLong(1);
                }
            }
            //Get the amount of data sent by the biggest request, we assume here that 1 character = 1 byte
            try (PreparedStatement stmt = this.storageConnection.prepareStatement(SQL_BIGGEST_REQUEST_AMOUNT_DATA_SENT)) {
                try (ResultSet rst = stmt.executeQuery()) {
                    biggestRequestAmountDataSent = rst.getLong(1);
                }
            }
            //Get the maximum number of hits sent in a second
            try (PreparedStatement stmt = this.storageConnection.prepareStatement(SQL_MAX_HITS_BY_SECOND)) {
                try (ResultSet rst = stmt.executeQuery()) {
                    maxHitsBySecond = rst.getLong(1);
                }
            }
        }
        //Get the size of the file on the disk
        String fileLocation = this.url.replace("jdbc:sqlite:", "").trim();
        long fileSize = Paths.get(fileLocation).toFile().length();
        //Build the VO and return it
        return new DBStats(fileSize, recordsCount, totalAmountDataSent, biggestRequestAmountDataSent, maxHitsBySecond);
    }

    /**
     * Ensure the connection to the DB is valid.
     *
     * @throws Exception If connection cannot be verified or opened.
     */
    private void ensureDBState() throws Exception {
        //Verify that the DB connection is still opened
        if (this.storageConnection.isClosed()) {
            //Get new one
            this.trace.writeLog("Open new connection to the storage.");
            this.storageConnection = DriverManager.getConnection(url);
            this.storageConnection.setAutoCommit(true);
        }
    }

    /**
     * Unloads the extension by releasing the DB connection.
     */
    @Override
    public void extensionUnloaded() {
        try {
            if (this.storageConnection != null && !this.storageConnection.isClosed()) {
                this.storageConnection.close();
                this.trace.writeLog("Connection to the storage released.");
            }
        } catch (Exception e) {
            this.trace.writeLog("Cannot close the connection to the storage: " + e.getMessage());
        }
    }
}
