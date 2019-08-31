package burp;

import javax.swing.JFileChooser;
import java.io.File;

/**
 * Contains utilities methods.
 */
class Utilities {

    /**
     * Create and configure a UI to select a DB file
     * @return a instance of a JFileChooser ready to use
     */
    static JFileChooser createDBFileChooser() {
        JFileChooser customStoreFileNameFileChooser = new JFileChooser();
        customStoreFileNameFileChooser.setDialogTitle("Select the DB file to use...");
        customStoreFileNameFileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
        customStoreFileNameFileChooser.setDialogType(JFileChooser.SAVE_DIALOG);
        customStoreFileNameFileChooser.setDragEnabled(false);
        customStoreFileNameFileChooser.setMultiSelectionEnabled(false);
        customStoreFileNameFileChooser.setAcceptAllFileFilterUsed(false);
        customStoreFileNameFileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        customStoreFileNameFileChooser.setFileHidingEnabled(true);
        return customStoreFileNameFileChooser;
    }
}
