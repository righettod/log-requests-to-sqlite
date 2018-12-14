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

    /**
     * Amount of data sent by the biggest request sent.
     */
    private long biggestRequestSize;

    /**
     * Maximum number of hits sent in a second.
     */
    private long maxHitsBySecond;


    DBStats(long sizeOnDisk, long totalRecordCount, long totalRequestsSize, long biggestRequestSize, long maxHitsBySecond) {
        this.sizeOnDisk = sizeOnDisk;
        this.totalRecordCount = totalRecordCount;
        this.totalRequestsSize = totalRequestsSize;
        this.biggestRequestSize = biggestRequestSize;
        this.maxHitsBySecond = maxHitsBySecond;
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

    long getBiggestRequestSize() {
        return biggestRequestSize;
    }

    public long getMaxHitsBySecond() {
        return maxHitsBySecond;
    }
}
