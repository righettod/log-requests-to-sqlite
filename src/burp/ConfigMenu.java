package burp;

import javax.swing.AbstractAction;
import javax.swing.JCheckBoxMenuItem;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;

/**
 * Menu to configure the extension options.
 */
class ConfigMenu implements Runnable, IExtensionStateListener {

    /**
     * Expose the configuration option for the restriction of the logging of requests in defined target scope.
     */
    static volatile boolean ONLY_INCLUDE_REQUESTS_FROM_SCOPE = Boolean.FALSE;

    /**
     * Expose the configuration option for the exclusion of the image resource requests from the logging.
     */
    static volatile boolean EXCLUDE_IMAGE_RESOURCE_REQUESTS = Boolean.FALSE;

    /**
     * Expose the list of all possible extensions of image resource to work in combination with the option "EXCLUDE_IMAGE_RESOURCE_REQUESTS".
     */
    static final List<String> IMAGE_RESOURCE_EXTENSIONS = new ArrayList<>();

    /**
     * Expose the configuration option to allow the user to pause the logging.
     */
    static volatile boolean IS_LOGGING_PAUSED = Boolean.FALSE;

    /**
     * Option configuration key for the restriction of the logging of requests in defined target scope.
     */
    private static final String ONLY_INCLUDE_REQUESTS_FROM_SCOPE_CFG_KEY = "ONLY_INCLUDE_REQUESTS_FROM_SCOPE";

    /**
     * Option configuration key for the exclusion of the image resource requests from the logging.
     */
    private static final String EXCLUDE_IMAGE_RESOURCE_REQUESTS_CFG_KEY = "EXCLUDE_IMAGE_RESOURCE_REQUESTS";

    /**
     * Option configuration key to allow the user to use a custom location and name for the DB file.
     */
    public static final String DB_FILE_CUSTOM_LOCATION_CFG_KEY = "DB_FILE_CUSTOM_LOCATION";

    /**
     * Option configuration key to allow the user to pause the logging.
     */
    public static final String PAUSE_LOGGING_CFG_KEY = "PAUSE_LOGGING";

    /**
     * Extension root configuration menu.
     */
    private JMenu cfgMenu;

    /**
     * Ref on Burp tool to manipulate the HTTP requests and have access to API to identify the source of the activity (tool name).
     */
    private IBurpExtenderCallbacks callbacks;

    /**
     * Ref on project logger.
     */
    private Trace trace;

    /**
     * Ref on activity logger in order to enable the access to the DB statistics.
     */
    private ActivityLogger activityLogger;

    /**
     * Constructor.
     *
     * @param callbacks      Ref on Burp tool to manipulate the HTTP requests and have access to API to identify the source of the activity (tool name).
     * @param trace          Ref on project logger.
     * @param activityLogger Ref on activity logger in order to enable the access to the DB statistics.
     */
    ConfigMenu(IBurpExtenderCallbacks callbacks, Trace trace, ActivityLogger activityLogger) {
        this.callbacks = callbacks;
        this.trace = trace;
        this.activityLogger = activityLogger;
        String value;
        //Load the extension settings
        if (IMAGE_RESOURCE_EXTENSIONS.isEmpty()) {
            ResourceBundle settingsBundle = ResourceBundle.getBundle("settings");
            value = settingsBundle.getString("image.extensions").replaceAll(" ", "").toLowerCase(Locale.US);
            Collections.addAll(IMAGE_RESOURCE_EXTENSIONS, value.split(","));
            this.trace.writeLog("Image resource extensions list successfully loaded: " + IMAGE_RESOURCE_EXTENSIONS.toString());
        }
        //Load the save state of the options
        value = this.callbacks.loadExtensionSetting(ONLY_INCLUDE_REQUESTS_FROM_SCOPE_CFG_KEY);
        ONLY_INCLUDE_REQUESTS_FROM_SCOPE = Boolean.parseBoolean(value);
        value = this.callbacks.loadExtensionSetting(ONLY_INCLUDE_REQUESTS_FROM_SCOPE_CFG_KEY);
        EXCLUDE_IMAGE_RESOURCE_REQUESTS = Boolean.parseBoolean(value);
        value = this.callbacks.loadExtensionSetting(PAUSE_LOGGING_CFG_KEY);
        IS_LOGGING_PAUSED = Boolean.parseBoolean(value);
    }

    /**
     * Build the options menu used to configure the extension.
     */
    @Override
    public void run() {
        //Build the menu
        this.cfgMenu = new JMenu("Log Requests to SQLite");
        //Add the sub menu to restrict the logging of requests in defined target scope
        String menuText = "Log only requests from defined target scope";
        final JCheckBoxMenuItem subMenuRestrictToScope = new JCheckBoxMenuItem(menuText, ONLY_INCLUDE_REQUESTS_FROM_SCOPE);
        subMenuRestrictToScope.addActionListener(new AbstractAction(menuText) {
            public void actionPerformed(ActionEvent e) {
                if (subMenuRestrictToScope.isSelected()) {
                    ConfigMenu.this.callbacks.saveExtensionSetting(ONLY_INCLUDE_REQUESTS_FROM_SCOPE_CFG_KEY, Boolean.TRUE.toString());
                    ConfigMenu.ONLY_INCLUDE_REQUESTS_FROM_SCOPE = Boolean.TRUE;
                    ConfigMenu.this.trace.writeLog("From now, only requests from defined target scope will be logged.");
                } else {
                    ConfigMenu.this.callbacks.saveExtensionSetting(ONLY_INCLUDE_REQUESTS_FROM_SCOPE_CFG_KEY, Boolean.FALSE.toString());
                    ConfigMenu.ONLY_INCLUDE_REQUESTS_FROM_SCOPE = Boolean.FALSE;
                    ConfigMenu.this.trace.writeLog("From now, requests that are not in defined target scope will be also logged.");
                }
            }
        });
        this.cfgMenu.add(subMenuRestrictToScope);
        //Add the sub menu to exclude the image resource requests from the logging.
        menuText = "Exclude the image resource requests";
        final JCheckBoxMenuItem subMenuExcludeImageResources = new JCheckBoxMenuItem(menuText, EXCLUDE_IMAGE_RESOURCE_REQUESTS);
        subMenuExcludeImageResources.addActionListener(new AbstractAction(menuText) {
            public void actionPerformed(ActionEvent e) {
                if (subMenuExcludeImageResources.isSelected()) {
                    ConfigMenu.this.callbacks.saveExtensionSetting(EXCLUDE_IMAGE_RESOURCE_REQUESTS_CFG_KEY, Boolean.TRUE.toString());
                    ConfigMenu.EXCLUDE_IMAGE_RESOURCE_REQUESTS = Boolean.TRUE;
                    ConfigMenu.this.trace.writeLog("From now, requests for image resource will not be logged.");
                } else {
                    ConfigMenu.this.callbacks.saveExtensionSetting(EXCLUDE_IMAGE_RESOURCE_REQUESTS_CFG_KEY, Boolean.FALSE.toString());
                    ConfigMenu.EXCLUDE_IMAGE_RESOURCE_REQUESTS = Boolean.FALSE;
                    ConfigMenu.this.trace.writeLog("From now, requests for image resource will be logged.");
                }
            }
        });
        this.cfgMenu.add(subMenuExcludeImageResources);
        //Add the menu to pause the logging
        menuText = "Pause the logging";
        final JCheckBoxMenuItem subMenuPauseTheLogging = new JCheckBoxMenuItem(menuText, IS_LOGGING_PAUSED);
        subMenuPauseTheLogging.addActionListener(new AbstractAction(menuText) {
            public void actionPerformed(ActionEvent e) {
                if (subMenuPauseTheLogging.isSelected()) {
                    ConfigMenu.this.callbacks.saveExtensionSetting(PAUSE_LOGGING_CFG_KEY, Boolean.TRUE.toString());
                    ConfigMenu.IS_LOGGING_PAUSED = Boolean.TRUE;
                    ConfigMenu.this.trace.writeLog("From now, logging is paused.");
                } else {
                    ConfigMenu.this.callbacks.saveExtensionSetting(PAUSE_LOGGING_CFG_KEY, Boolean.FALSE.toString());
                    ConfigMenu.IS_LOGGING_PAUSED = Boolean.FALSE;
                    String dbPath = callbacks.loadExtensionSetting(ConfigMenu.DB_FILE_CUSTOM_LOCATION_CFG_KEY);
                    String msg = "From now, logging is enabled and stored in database file '" + dbPath + "'.";
                    ConfigMenu.this.trace.writeLog(msg);
                }
            }
        });
        this.cfgMenu.add(subMenuPauseTheLogging);
        //Add the menu to change the DB file
        menuText = "Change the DB file";
        final JMenuItem subMenuDBFileLocationMenuItem = new JMenuItem(menuText);
        subMenuDBFileLocationMenuItem.addActionListener(
                new AbstractAction(menuText) {
                    public void actionPerformed(ActionEvent e) {
                        try {
                            String title = "Change the DB file";
                            if (!ConfigMenu.IS_LOGGING_PAUSED) {
                                JOptionPane.showMessageDialog(ConfigMenu.getBurpFrame(), "Logging must be paused prior to update the DB file location!", title, JOptionPane.WARNING_MESSAGE);
                            } else {
                                String customStoreFileName = callbacks.loadExtensionSetting(ConfigMenu.DB_FILE_CUSTOM_LOCATION_CFG_KEY);
                                JFileChooser customStoreFileNameFileChooser = Utilities.createDBFileChooser();
                                int dbFileSelectionReply = customStoreFileNameFileChooser.showDialog(getBurpFrame(), "Use");
                                if (dbFileSelectionReply == JFileChooser.APPROVE_OPTION) {
                                    customStoreFileName = customStoreFileNameFileChooser.getSelectedFile().getAbsolutePath().replaceAll("\\\\", "/");
                                    activityLogger.updateStoreLocation(customStoreFileName);
                                    callbacks.saveExtensionSetting(ConfigMenu.DB_FILE_CUSTOM_LOCATION_CFG_KEY, customStoreFileName);
                                    JOptionPane.showMessageDialog(getBurpFrame(), "DB file updated to use:\n\r" + customStoreFileName, title, JOptionPane.INFORMATION_MESSAGE);
                                } else {
                                    JOptionPane.showMessageDialog(getBurpFrame(), "The following database file will continue to be used:\n\r" + customStoreFileName, title, JOptionPane.INFORMATION_MESSAGE);
                                }
                            }
                        } catch (Exception exp) {
                            ConfigMenu.this.trace.writeLog("Cannot update DB file location: " + exp.getMessage());
                        }
                    }
                }
        );
        this.cfgMenu.add(subMenuDBFileLocationMenuItem);
        //Add the sub menu to get statistics about the DB.
        menuText = "Get statistics about the logged events";
        final JMenuItem subMenuDBStatsMenuItem = new JMenuItem(menuText);
        subMenuDBStatsMenuItem.addActionListener(
                new AbstractAction(menuText) {
                    public void actionPerformed(ActionEvent e) {
                        try {
                            //Get the data
                            DBStats stats = ConfigMenu.this.activityLogger.getEventsStats();
                            //Build the message
                            String buffer = "Size of the database file on the disk: \n\r" + formatStat(stats.getSizeOnDisk()) + ".\n\r";
                            buffer += "Amount of data sent by the biggest HTTP request: \n\r" + formatStat(stats.getBiggestRequestSize()) + ".\n\r";
                            buffer += "Total amount of data sent via HTTP requests: \n\r" + formatStat(stats.getTotalRequestsSize()) + ".\n\r";
                            buffer += "Total number of records in the database: \n\r" + stats.getTotalRecordCount() + " HTTP requests.\n\r";
                            buffer += "Maximum number of hits sent in a second: \n\r" + stats.getMaxHitsBySecond() + " Hits.";
                            //Display the information via the UI
                            JOptionPane.showMessageDialog(ConfigMenu.getBurpFrame(), buffer, "Events statistics", JOptionPane.INFORMATION_MESSAGE);
                        } catch (Exception exp) {
                            ConfigMenu.this.trace.writeLog("Cannot obtains statistics about events: " + exp.getMessage());
                        }
                    }
                }
        );
        this.cfgMenu.add(subMenuDBStatsMenuItem);
        //Add it to BURP menu
        JFrame burpFrame = ConfigMenu.getBurpFrame();
        if (burpFrame != null) {
            JMenuBar jMenuBar = burpFrame.getJMenuBar();
            jMenuBar.add(this.cfgMenu);
            jMenuBar.repaint();
            this.trace.writeLog("Configuration menu added.");
        } else {
            this.trace.writeLog("Cannot add the configuration menu (ref on the BURP frame is null).");
        }
    }

    /**
     * Remove the menu from BURP menu bar.
     *
     * @see "https://github.com/PortSwigger/param-miner/blob/master/src/burp/Utilities.java"
     */
    @Override
    public void extensionUnloaded() {
        JFrame burpFrame = ConfigMenu.getBurpFrame();
        if (burpFrame != null && this.cfgMenu != null) {
            JMenuBar jMenuBar = burpFrame.getJMenuBar();
            jMenuBar.remove(this.cfgMenu);
            jMenuBar.repaint();
            this.trace.writeLog("Configuration menu removed.");
        } else {
            this.trace.writeLog("Cannot remove the configuration menu (ref on the BURP frame is null).");
        }
    }

    /**
     * Get a reference on the BURP main frame.
     *
     * @return BURP main frame.
     * @see "https://github.com/PortSwigger/param-miner/blob/master/src/burp/Utilities.java"
     */
    static JFrame getBurpFrame() {
        for (Frame f : Frame.getFrames()) {
            if (f.isVisible() && f.getTitle().startsWith(("Burp Suite"))) {
                return (JFrame) f;
            }
        }
        return null;
    }

    /**
     * Format a statistic value in KB, MB or GB according to the value passed.
     *
     * @param stat Number of bytes.
     * @return Formatted value.
     */
    static String formatStat(long stat) {

        //Units
        double oneKB = 1024;
        double oneMB = 1048576;
        double oneGB = 1073741824;

        //Determine the unit the use
        double unit = oneKB;
        String unitLabel = "Kb";
        if (stat >= oneGB) {
            unit = oneGB;
            unitLabel = "Gb";
        } else if (stat >= oneMB) {
            unit = oneMB;
            unitLabel = "Mb";
        }

        //Computing
        double amount = stat / unit;
        return String.format("%.2f %s", amount, unitLabel);
    }
}
