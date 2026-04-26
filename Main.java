import java.util.*;

// ----------------------------------------------------------------------
// HashUtils – provides hash functions and fingerprint extraction
// ----------------------------------------------------------------------
class HashUtils {
    // Simple multiplicative hash for strings
    public static int hash1(String key) {
        int h = key.hashCode();
        h ^= (h >>> 20) ^ (h >>> 12);
        h ^= (h >>> 7) ^ (h >>> 4);
        return Math.abs(h);
    }

    // Offset hash derived from fingerprint
    public static int hashOffset(int fingerprint) {
        // Mix bits to distribute offsets
        int h = fingerprint * 0x9E3779B9;
        h ^= (h >>> 16);
        return Math.abs(h);
    }

    // Extract a non-zero fingerprint (8 bits) from a key
    public static int fingerprint(String key) {
        int h = hash1(key);
        int fp = h & 0xFF;          // keep lower 8 bits
        if (fp == 0) fp = 1;        // reserve 0 for empty slot
        return fp;
    }

    // Convert fingerprint to 8-bit binary string for display
    public static String toBinary(int fingerprint) {
        String bin = Integer.toBinaryString(fingerprint);
        while (bin.length() < 8) bin = "0" + bin;
        return bin;
    }
}

// ----------------------------------------------------------------------
// Common interface for both filters
// ----------------------------------------------------------------------
interface CuckooFilter {
    boolean insert(String key);
    boolean lookup(String key);
    boolean delete(String key);
    void display();
    String getFingerprintInfo(String key);  // returns formatted fingerprint + indices
    int getLoad();                           // current number of stored items
    int getCapacity();                       // total number of slots
    int getEvictionCount();                  // total kicks performed
}

// ----------------------------------------------------------------------
// Bucketed Cuckoo Filter (2D: buckets × slots)
// ----------------------------------------------------------------------
class BucketedCuckooFilter implements CuckooFilter {
    // Slot inside a bucket
    private static class Slot {
        int fingerprint;    // 0 means empty; otherwise 1..255
        boolean isPrimary;  // true if this slot holds the primary bucket (i1)

        Slot() {
            fingerprint = 0;
            isPrimary = false;
        }
    }

    private final int numBuckets;
    private final int bucketSize;   // slots per bucket
    private final Slot[][] table;
    private int itemCount;
    private int evictionCount;      // total kicks during all insertions
    private static final int MAX_KICKS = 500;
    private final Random rand = new Random();

    public BucketedCuckooFilter(int numBuckets, int bucketSize) {
        this.numBuckets = numBuckets;
        this.bucketSize = bucketSize;
        table = new Slot[numBuckets][bucketSize];
        for (int i = 0; i < numBuckets; i++) {
            for (int j = 0; j < bucketSize; j++) {
                table[i][j] = new Slot();
            }
        }
        itemCount = 0;
        evictionCount = 0;
    }

    // Compute alternate bucket for a given fingerprint and current bucket+parity
    private int alternateBucket(int currBucket, int fingerprint, boolean isPrimary) {
        int offset = HashUtils.hashOffset(fingerprint) % numBuckets;
        if (isPrimary) {
            return (currBucket + offset) % numBuckets;
        } else {
            return (currBucket - offset + numBuckets) % numBuckets;
        }
    }

    @Override
    public boolean insert(String key) {
        int fp = HashUtils.fingerprint(key);
        int i1 = HashUtils.hash1(key) % numBuckets;
        int offset = HashUtils.hashOffset(fp) % numBuckets;
        int i2 = (i1 + offset) % numBuckets;

        // try i1
        if (insertIntoBucket(i1, fp, true)) {
            itemCount++;
            return true;
        }
        // try i2
        if (insertIntoBucket(i2, fp, false)) {
            itemCount++;
            return true;
        }

        // Both buckets full → start cuckoo eviction
        int curBucket = rand.nextBoolean() ? i1 : i2;
        boolean curPrimary = (curBucket == i1);
        int curFp = fp;

        for (int kick = 0; kick < MAX_KICKS; kick++) {
            // pick a random slot from the current bucket (all occupied)
            Slot[] bucket = table[curBucket];
            int slotIdx = rand.nextInt(bucketSize);
            Slot victim = bucket[slotIdx];

            // evict victim
            int victimFp = victim.fingerprint;
            boolean victimPrimary = victim.isPrimary;

            // place current item in this slot
            victim.fingerprint = curFp;
            victim.isPrimary = curPrimary;
            evictionCount++;

            // now re-insert victim
            int altBucket = alternateBucket(curBucket, victimFp, victimPrimary);
            boolean altPrimary = !victimPrimary;   // opposite of current

            if (insertIntoBucket(altBucket, victimFp, altPrimary)) {
                itemCount++;
                return true;
            }
            // continue with victim
            curBucket = altBucket;
            curPrimary = altPrimary;
            curFp = victimFp;
        }
        return false;   // insertion failed after max kicks
    }

    // Try to place a fingerprint into a bucket with the given parity flag
    private boolean insertIntoBucket(int bucketIdx, int fp, boolean isPrimary) {
        Slot[] bucket = table[bucketIdx];
        for (Slot slot : bucket) {
            if (slot.fingerprint == 0) {
                slot.fingerprint = fp;
                slot.isPrimary = isPrimary;
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean lookup(String key) {
        int fp = HashUtils.fingerprint(key);
        int i1 = HashUtils.hash1(key) % numBuckets;
        int offset = HashUtils.hashOffset(fp) % numBuckets;
        int i2 = (i1 + offset) % numBuckets;

        return bucketContains(i1, fp) || bucketContains(i2, fp);
    }

    private boolean bucketContains(int bucketIdx, int fp) {
        for (Slot slot : table[bucketIdx]) {
            if (slot.fingerprint == fp) return true;
        }
        return false;
    }

    @Override
    public boolean delete(String key) {
        int fp = HashUtils.fingerprint(key);
        int i1 = HashUtils.hash1(key) % numBuckets;
        int offset = HashUtils.hashOffset(fp) % numBuckets;
        int i2 = (i1 + offset) % numBuckets;

        if (deleteFromBucket(i1, fp)) {
            itemCount--;
            return true;
        }
        if (deleteFromBucket(i2, fp)) {
            itemCount--;
            return true;
        }
        return false;
    }

    private boolean deleteFromBucket(int bucketIdx, int fp) {
        for (Slot slot : table[bucketIdx]) {
            if (slot.fingerprint == fp) {
                slot.fingerprint = 0;
                return true;
            }
        }
        return false;
    }

    @Override
    public void display() {
        System.out.println("\n[BUCKETED CUCKOO FILTER]");
        System.out.println("Buckets: " + numBuckets + " | Slots/bucket: " + bucketSize +
                           " | Total slots: " + (numBuckets * bucketSize));
        System.out.println("Items stored: " + itemCount + " | Evictions: " + evictionCount);
        for (int i = 0; i < numBuckets; i++) {
            System.out.printf("Bucket %2d: ", i);
            for (Slot slot : table[i]) {
                if (slot.fingerprint == 0)
                    System.out.print("[  empty ] ");
                else
                    System.out.printf("[%3d (%s)] ",
                            slot.fingerprint, slot.isPrimary ? "P" : "S");
            }
            System.out.println();
        }
    }

    @Override
    public String getFingerprintInfo(String key) {
        int fp = HashUtils.fingerprint(key);
        int i1 = HashUtils.hash1(key) % numBuckets;
        int offset = HashUtils.hashOffset(fp) % numBuckets;
        int i2 = (i1 + offset) % numBuckets;
        return String.format(" Fingerprint: %s (%d)\n Bucket1: %d, Bucket2: %d",
                HashUtils.toBinary(fp), fp, i1, i2);
    }

    @Override
    public int getLoad() { return itemCount; }

    @Override
    public int getCapacity() { return numBuckets * bucketSize; }

    @Override
    public int getEvictionCount() { return evictionCount; }
}

// ----------------------------------------------------------------------
// Windowed Cuckoo Filter (1D overlapping windows)
// ----------------------------------------------------------------------
class WindowedCuckooFilter implements CuckooFilter {
    // Slot in the 1D array
    private static class Slot {
        int fingerprint;     // 0 = empty
        int windowIndex;     // the window (start index) through which this item was inserted
        boolean isPrimary;   // true if this window is the primary (i1) for the item

        Slot() {
            fingerprint = 0;
            windowIndex = -1;
            isPrimary = false;
        }
    }

    private final int M;            // total number of slots (array length)
    private final int numWindows;   // windows = M - 1 (each window is 2 slots)
    private final Slot[] slots;
    private int itemCount;
    private int evictionCount;
    private static final int MAX_KICKS = 500;
    private final Random rand = new Random();

    public WindowedCuckooFilter(int M) {
        // M must be at least 2
        this.M = M;
        this.numWindows = M - 1;
        slots = new Slot[M];
        for (int i = 0; i < M; i++) {
            slots[i] = new Slot();
        }
        itemCount = 0;
        evictionCount = 0;
    }

    // Compute the alternate window for a given item (current window, fingerprint, parity)
    private int alternateWindow(int currWindow, int fp, boolean isPrimary) {
        int offset = HashUtils.hashOffset(fp) % numWindows;
        if (isPrimary) {
            return (currWindow + offset) % numWindows;
        } else {
            return (currWindow - offset + numWindows) % numWindows;
        }
    }

    // Try to insert into a specific window (w). The window covers slots w and w+1.
    private boolean insertIntoWindow(int w, int fp, boolean isPrimary) {
        // Check slot w
        if (slots[w].fingerprint == 0) {
            slots[w].fingerprint = fp;
            slots[w].windowIndex = w;
            slots[w].isPrimary = isPrimary;
            return true;
        }
        // Check slot w+1
        if (slots[w + 1].fingerprint == 0) {
            slots[w + 1].fingerprint = fp;
            slots[w + 1].windowIndex = w;
            slots[w + 1].isPrimary = isPrimary;
            return true;
        }
        return false;
    }

    @Override
    public boolean insert(String key) {
        int fp = HashUtils.fingerprint(key);
        int i1 = HashUtils.hash1(key) % numWindows;
        int offset = HashUtils.hashOffset(fp) % numWindows;
        int i2 = (i1 + offset) % numWindows;

        // try primary window
        if (insertIntoWindow(i1, fp, true)) {
            itemCount++;
            return true;
        }
        // try secondary window
        if (insertIntoWindow(i2, fp, false)) {
            itemCount++;
            return true;
        }

        // Both windows full → cuckoo eviction
        // Choose a random window among i1, i2 to start
        int curWindow = rand.nextBoolean() ? i1 : i2;
        boolean curPrimary = (curWindow == i1);
        int curFp = fp;

        for (int kick = 0; kick < MAX_KICKS; kick++) {
            // current window is curWindow (slots curWindow and curWindow+1, both occupied)
            int slotIdx = curWindow + rand.nextInt(2);   // pick one of the two slots
            Slot victim = slots[slotIdx];

            int victimFp = victim.fingerprint;
            int victimWindow = victim.windowIndex;
            boolean victimPrimary = victim.isPrimary;

            // place the current item into the victim slot
            victim.fingerprint = curFp;
            victim.windowIndex = curWindow;
            victim.isPrimary = curPrimary;
            evictionCount++;

            // move to the alternate window for the evicted item
            int altWindow = alternateWindow(victimWindow, victimFp, victimPrimary);
            boolean altPrimary = !victimPrimary;

            if (insertIntoWindow(altWindow, victimFp, altPrimary)) {
                itemCount++;
                return true;
            }
            // if also full, continue with victim
            curWindow = altWindow;
            curPrimary = altPrimary;
            curFp = victimFp;
        }
        return false; // failed
    }

    @Override
    public boolean lookup(String key) {
        int fp = HashUtils.fingerprint(key);
        int i1 = HashUtils.hash1(key) % numWindows;
        int offset = HashUtils.hashOffset(fp) % numWindows;
        int i2 = (i1 + offset) % numWindows;

        // check both windows
        return (slots[i1].fingerprint == fp || slots[i1 + 1].fingerprint == fp) ||
               (slots[i2].fingerprint == fp || slots[i2 + 1].fingerprint == fp);
    }

    @Override
    public boolean delete(String key) {
        int fp = HashUtils.fingerprint(key);
        int i1 = HashUtils.hash1(key) % numWindows;
        int offset = HashUtils.hashOffset(fp) % numWindows;
        int i2 = (i1 + offset) % numWindows;

        if (tryDeleteFromWindow(i1, fp)) {
            itemCount--;
            return true;
        }
        if (tryDeleteFromWindow(i2, fp)) {
            itemCount--;
            return true;
        }
        return false;
    }

    private boolean tryDeleteFromWindow(int w, int fp) {
        if (slots[w].fingerprint == fp) {
            slots[w].fingerprint = 0;
            return true;
        }
        if (slots[w + 1].fingerprint == fp) {
            slots[w + 1].fingerprint = 0;
            return true;
        }
        return false;
    }

    @Override
    public void display() {
        System.out.println("\n[WINDOWED CUCKOO FILTER]");
        System.out.println("Slots: " + M + " | Windows: " + numWindows +
                           " (window size = 2)");
        System.out.println("Items stored: " + itemCount + " | Evictions: " + evictionCount);
        for (int i = 0; i < M; i++) {
            Slot s = slots[i];
            if (s.fingerprint == 0) {
                System.out.printf("Slot %2d: [  empty ]\n", i);
            } else {
                System.out.printf("Slot %2d: [%3d] win=%d %s\n",
                        i, s.fingerprint, s.windowIndex, s.isPrimary ? "(P)" : "(S)");
            }
        }
    }

    @Override
    public String getFingerprintInfo(String key) {
        int fp = HashUtils.fingerprint(key);
        int i1 = HashUtils.hash1(key) % numWindows;
        int offset = HashUtils.hashOffset(fp) % numWindows;
        int i2 = (i1 + offset) % numWindows;
        return String.format(" Fingerprint: %s (%d)\n Window1: %d (slots %d-%d), Window2: %d (slots %d-%d)",
                HashUtils.toBinary(fp), fp, i1, i1, i1+1, i2, i2, i2+1);
    }

    @Override
    public int getLoad() { return itemCount; }

    @Override
    public int getCapacity() { return M; }

    @Override
    public int getEvictionCount() { return evictionCount; }
}

// ----------------------------------------------------------------------
// PerformanceAnalyzer – measures time, FPR, load factor
// ----------------------------------------------------------------------
class PerformanceAnalyzer {
    // Run a full test on a given filter
    public static void runTest(CuckooFilter filter, int insertCount, int queryCount) {
        Random rand = new Random(42);
        Set<String> inserted = new LinkedHashSet<>();
        List<String> testSet = new ArrayList<>();

        // Generate insert data (unique random strings)
        for (int i = 0; i < insertCount; i++) {
            String s;
            do {
                s = "item" + rand.nextInt(1000000);
            } while (inserted.contains(s));
            inserted.add(s);
            testSet.add(s);
        }

        // Measure insertion time
        long start = System.nanoTime();
        int successInsert = 0;
        for (String s : testSet) {
            if (filter.insert(s)) successInsert++;
        }
        long insertTime = System.nanoTime() - start;

        // Measure lookup time (on inserted items)
        start = System.nanoTime();
        int found = 0;
        for (String s : testSet) {
            if (filter.lookup(s)) found++;
        }
        long lookupTime = System.nanoTime() - start;

        // Measure deletion time (delete half the items, if possible)
        List<String> toDelete = new ArrayList<>(testSet.subList(0, testSet.size() / 2));
        start = System.nanoTime();
        int deleted = 0;
        for (String s : toDelete) {
            if (filter.delete(s)) deleted++;
        }
        long deleteTime = System.nanoTime() - start;

        // False positive test: query strings that were NOT inserted
        Set<String> notInserted = new LinkedHashSet<>();
        while (notInserted.size() < queryCount) {
            String s = "rand" + rand.nextInt(2000000);
            if (!inserted.contains(s)) notInserted.add(s);
        }
        int falsePos = 0;
        for (String s : notInserted) {
            if (filter.lookup(s)) falsePos++;
        }
        double fpr = (double) falsePos / queryCount;

        // Load factor
        double loadFactor = (double) filter.getLoad() / filter.getCapacity();

        // Print report
        System.out.println("\n==================== PERFORMANCE REPORT ====================");
        System.out.printf("Insertion attempts  : %d  (succeeded: %d)%n", insertCount, successInsert);
        System.out.printf("Insertion time (ns) : %d (avg %.1f ns/op)%n", insertTime, insertTime/(double)insertCount);
        System.out.printf("Lookup time (ns)    : %d (avg %.1f ns/op) [found: %d/%d]%n",
                lookupTime, lookupTime/(double)insertCount, found, insertCount);
        System.out.printf("Deletion time (ns)  : %d (avg %.1f ns/op) [deleted: %d/%d]%n",
                deleteTime, deleteTime/(double)toDelete.size(), deleted, toDelete.size());
        System.out.printf("False positive rate : %.4f (%d / %d)%n", fpr, falsePos, queryCount);
        System.out.printf("Load factor         : %.4f (%d / %d)%n", loadFactor, filter.getLoad(), filter.getCapacity());
        System.out.printf("Total evictions     : %d%n", filter.getEvictionCount());
        System.out.println("============================================================");
    }

    // Compare bucketed vs windowed with the same dataset
    public static void compareBoth(int insertCount, int queryCount,
                                   int bucketedBuckets, int bucketSize,
                                   int windowedSlots) {
        CuckooFilter bucketed = new BucketedCuckooFilter(bucketedBuckets, bucketSize);
        CuckooFilter windowed = new WindowedCuckooFilter(windowedSlots);

        System.out.println("\n========== COMPARISON: BUCKETED vs WINDOWED ==========");
        System.out.printf("Configuration: Buckets=%d×%d (total %d) | Window slots=%d (total %d)%n",
                bucketedBuckets, bucketSize, bucketed.getCapacity(),
                windowedSlots, windowed.getCapacity());

        System.out.println("\n>>> Testing BUCKETED filter...");
        runTest(bucketed, insertCount, queryCount);

        System.out.println("\n>>> Testing WINDOWED filter...");
        runTest(windowed, insertCount, queryCount);

        // Additional remark: candidate positions
        System.out.println("\n--- Candidate Positions Analysis ---");
        System.out.println("Bucketed filter: each key has 2 buckets × " + bucketSize +
                           " slots = " + (2 * bucketSize) + " possible slots.");
        System.out.println("Windowed filter: each key has 2 windows × 2 slots = 4 possible slots.");
        System.out.println("Thus windowed uses fewer candidate positions, which can help reduce");
        System.out.println("false positives at the expense of slightly lower load capacity.");
        System.out.println("===========================================================");
    }
}

// ----------------------------------------------------------------------
// Main – CLI menu (FIXED: persistent filter instances)
// ----------------------------------------------------------------------
public class Main {
    private static Scanner scanner = new Scanner(System.in);

    // Default sizes
    private static final int BUCKETED_BUCKETS = 16;
    private static final int BUCKETED_SLOTS_PER_BUCKET = 4;
    private static final int WINDOWED_SLOTS = 64;

    // Persistent filter instances – these live for the whole session
    private static CuckooFilter bucketedFilter = new BucketedCuckooFilter(BUCKETED_BUCKETS, BUCKETED_SLOTS_PER_BUCKET);
    private static CuckooFilter windowedFilter = new WindowedCuckooFilter(WINDOWED_SLOTS);

    public static void main(String[] args) {
        System.out.println("============================================================");
        System.out.println("                 CUCKOO FILTER IMPLEMENTATION                ");
        System.out.println("============================================================");

        while (true) {
            System.out.println("\n1. Insert element");
            System.out.println("2. Search element");
            System.out.println("3. Delete element");
            System.out.println("4. Show fingerprint of key");
            System.out.println("5. Print filter structure");
            System.out.println("6. Compare both filters");
            System.out.println("7. Run performance test");
            System.out.println("8. Exit");
            System.out.print("Choose an option: ");
            int choice = readInt();

            switch (choice) {
                case 1: insertElement(); break;
                case 2: searchElement(); break;
                case 3: deleteElement(); break;
                case 4: showFingerprint(); break;
                case 5: printStructure(); break;
                case 6: compareBoth(); break;
                case 7: performanceTest(); break;
                case 8:
                    System.out.println("Exiting...");
                    return;
                default:
                    System.out.println("Invalid option. Try again.");
            }
        }
    }

    // ---------- Helper: choose one of the persistent filters ----------
    private static CuckooFilter chooseFilter() {
        System.out.print("Select filter: 1. Bucketed  2. Windowed: ");
        int ch = readInt();
        if (ch == 1) return bucketedFilter;
        if (ch == 2) return windowedFilter;
        System.out.println("Invalid choice.");
        return null;
    }

    // ---------- Menu actions ----------
    private static void insertElement() {
        CuckooFilter filter = chooseFilter();
        if (filter == null) return;
        System.out.print("Enter key to insert: ");
        String key = scanner.next();
        String info = filter.getFingerprintInfo(key);
        boolean ok = filter.insert(key);
        System.out.println("\n-------------------------------");
        System.out.println("[" + (filter instanceof BucketedCuckooFilter ? "BUCKETED" : "WINDOWED") + " FILTER]");
        System.out.println("Inserting: " + key);
        System.out.println(info);
        System.out.println("Status: " + (ok ? "INSERTED" : "FAILED (table full)"));
        System.out.println("-------------------------------");
    }

    private static void searchElement() {
        CuckooFilter filter = chooseFilter();
        if (filter == null) return;
        System.out.print("Enter key to search: ");
        String key = scanner.next();
        boolean found = filter.lookup(key);
        String info = filter.getFingerprintInfo(key);
        System.out.println("\n-------------------------------");
        System.out.println("[" + (filter instanceof BucketedCuckooFilter ? "BUCKETED" : "WINDOWED") + " FILTER]");
        System.out.println("Searching: " + key);
        System.out.println(info);
        System.out.println("Status: " + (found ? "FOUND" : "NOT FOUND"));
        System.out.println("-------------------------------");
    }

    private static void deleteElement() {
        CuckooFilter filter = chooseFilter();
        if (filter == null) return;
        System.out.print("Enter key to delete: ");
        String key = scanner.next();
        boolean deleted = filter.delete(key);
        String info = filter.getFingerprintInfo(key);
        System.out.println("\n-------------------------------");
        System.out.println("[" + (filter instanceof BucketedCuckooFilter ? "BUCKETED" : "WINDOWED") + " FILTER]");
        System.out.println("Deleting: " + key);
        System.out.println(info);
        System.out.println("Status: " + (deleted ? "DELETED" : "NOT FOUND"));
        System.out.println("-------------------------------");
    }

    private static void showFingerprint() {
        System.out.print("Enter key to show fingerprint: ");
        String key = scanner.next();
        int fp = HashUtils.fingerprint(key);
        System.out.println("\n-------------------------------");
        System.out.println("Key: " + key);
        System.out.println("Fingerprint: " + HashUtils.toBinary(fp) + " (decimal " + fp + ")");
        System.out.println("-------------------------------");
    }

    private static void printStructure() {
        CuckooFilter filter = chooseFilter();
        if (filter == null) return;
        filter.display();
    }

    private static void compareBoth() {
        System.out.print("Enter number of elements to insert: ");
        int n = readInt();
        System.out.print("Enter number of queries for false positive test: ");
        int q = readInt();
        PerformanceAnalyzer.compareBoth(n, q,
                BUCKETED_BUCKETS, BUCKETED_SLOTS_PER_BUCKET, WINDOWED_SLOTS);
    }

    private static void performanceTest() {
        System.out.print("Select filter: 1. Bucketed  2. Windowed: ");
        int ch = readInt();
        CuckooFilter filter;
        if (ch == 1) filter = new BucketedCuckooFilter(BUCKETED_BUCKETS, BUCKETED_SLOTS_PER_BUCKET);
        else if (ch == 2) filter = new WindowedCuckooFilter(WINDOWED_SLOTS);
        else { System.out.println("Invalid choice."); return; }

        System.out.print("Enter number of elements to insert: ");
        int n = readInt();
        System.out.print("Enter number of false-positive queries: ");
        int q = readInt();
        PerformanceAnalyzer.runTest(filter, n, q);
    }

    private static int readInt() {
        while (!scanner.hasNextInt()) {
            scanner.next();
            System.out.print("Enter a number: ");
        }
        return scanner.nextInt();
    }
}