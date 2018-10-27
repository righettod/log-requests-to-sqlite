package burp;

/**
 * VO object used to stored statistics information about the DB.
 */
class DBStats {
    /**
     * Size on the DB file on disk in bytes
     */
    private long sizeOnDisk;
    /**
     * Total number of record in the DB main table used
     */
    private long totalRecordCount;
    /**
     * Amount of data sent via the total size of all HTTP requests
     */
    private long totalRequestsSize;

    DBStats(long sizeOnDisk, long totalRecordCount, long totalRequestsSize) {
        this.sizeOnDisk = sizeOnDisk;
        this.totalRecordCount = totalRecordCount;
        this.totalRequestsSize = totalRequestsSize;
    }

    long getSizeOnDisk() {
        return sizeOnDisk;
    }

    long getTotalRecordCount() {
        return totalRecordCount;
    }

    long getTotalRequestsSize() {
        return totalRequestsSize;
    }
}
