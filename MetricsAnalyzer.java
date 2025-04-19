import java.io.*;
import java.time.*;
import java.time.format.*;
import java.util.*;
import java.util.regex.*;

public class MetricsAnalyzer {
    private static final String SV_LOG_FILE = "SVLogs.txt";
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static class SystemMetrics {
        // Communication metrics
        List<Long> svLatencies = new ArrayList<>();

        // Encryption metrics
        List<Double> encryptionRatios = new ArrayList<>();
        int hashVerificationSuccess = 0;
        int hashVerificationFailure = 0;

        // Error metrics
        int encryptionErrors = 0;
        int decryptionErrors = 0;
        int parsingErrors = 0;
    }

    public static void main(String[] args) {
        try {
            SystemMetrics metrics = new SystemMetrics();
            parseSVLogs(metrics);
            displayMetrics(metrics);
        } catch (Exception e) {
            System.err.println("Error analyzing metrics: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void parseSVLogs(SystemMetrics metrics) throws IOException {
        System.out.println("Analyzing SV communication logs...");

        Map<String, LocalDateTime> sendTimes = new HashMap<>();
        Map<String, Integer> originalSizes = new HashMap<>();
        Map<String, Integer> encryptedSizes = new HashMap<>();

        Pattern sendTimePattern = Pattern.compile("\\[(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})\\] Original data size: (\\d+) bytes");
        Pattern encryptedSizePattern = Pattern.compile("\\[(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})\\] Encrypted data with hash size: (\\d+) bytes");
        Pattern receiveTimePattern = Pattern.compile("\\[(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})\\] Decryption and hash verification successful");
        Pattern verificationFailPattern = Pattern.compile("\\[(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})\\] Hash verification failed");
        Pattern encryptionErrorPattern = Pattern.compile("\\[(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})\\] Error encrypting");
        Pattern decryptionErrorPattern = Pattern.compile("\\[(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})\\] Error decrypting");
        Pattern parsingErrorPattern = Pattern.compile("\\[(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})\\] Error parsing");

        try (BufferedReader reader = new BufferedReader(new FileReader(SV_LOG_FILE))) {
            String line;
            int messageCounter = 0;
            LocalDateTime lastSendTime = null;

            while ((line = reader.readLine()) != null) {
                Matcher sendMatcher = sendTimePattern.matcher(line);
                if (sendMatcher.find()) {
                    lastSendTime = LocalDateTime.parse(sendMatcher.group(1), DATE_FORMAT);
                    int originalSize = Integer.parseInt(sendMatcher.group(2));
                    String msgId = "sv-" + (++messageCounter);
                    sendTimes.put(msgId, lastSendTime);
                    originalSizes.put(msgId, originalSize);
                    continue;
                }

                Matcher encryptedMatcher = encryptedSizePattern.matcher(line);
                if (encryptedMatcher.find()) {
                    int encryptedSize = Integer.parseInt(encryptedMatcher.group(2));
                    String msgId = "sv-" + messageCounter;
                    encryptedSizes.put(msgId, encryptedSize);

                    if (originalSizes.containsKey(msgId)) {
                        double ratio = (double) encryptedSize / originalSizes.get(msgId);
                        metrics.encryptionRatios.add(ratio);
                    }
                    continue;
                }

                Matcher receiveMatcher = receiveTimePattern.matcher(line);
                if (receiveMatcher.find()) {
                    LocalDateTime receiveTime = LocalDateTime.parse(receiveMatcher.group(1), DATE_FORMAT);
                    metrics.hashVerificationSuccess++;

                    String closestMsgId = null;
                    LocalDateTime closestTime = null;

                    for (Map.Entry<String, LocalDateTime> entry : sendTimes.entrySet()) {
                        if (entry.getValue().isBefore(receiveTime)) {
                            if (closestTime == null || entry.getValue().isAfter(closestTime)) {
                                closestTime = entry.getValue();
                                closestMsgId = entry.getKey();
                            }
                        }
                    }

                    if (closestMsgId != null) {
                        long latencyMs = Duration.between(closestTime, receiveTime).toMillis();
                        metrics.svLatencies.add(latencyMs);
                    }
                    continue;
                }

                if (verificationFailPattern.matcher(line).find()) {
                    metrics.hashVerificationFailure++;
                    continue;
                }

                if (encryptionErrorPattern.matcher(line).find()) {
                    metrics.encryptionErrors++;
                } else if (decryptionErrorPattern.matcher(line).find()) {
                    metrics.decryptionErrors++;
                } else if (parsingErrorPattern.matcher(line).find()) {
                    metrics.parsingErrors++;
                }
            }
        }
    }

    private static void displayMetrics(SystemMetrics metrics) {
        System.out.println("\n--- System Metrics Report ---");

        System.out.println("SV Latencies (ms):");
        printListStats(metrics.svLatencies);

        System.out.println("Encryption Ratios:");
        printListStats(metrics.encryptionRatios);

        System.out.println("\nHash Verification:");
        System.out.println("  Successes: " + metrics.hashVerificationSuccess);
        System.out.println("  Failures: " + metrics.hashVerificationFailure);

        System.out.println("\nError Metrics:");
        System.out.println("  Encryption Errors: " + metrics.encryptionErrors);
        System.out.println("  Decryption Errors: " + metrics.decryptionErrors);
        System.out.println("  Parsing Errors: " + metrics.parsingErrors);
    }

    private static void printListStats(List<? extends Number> values) {
        if (values.isEmpty()) {
            System.out.println("  No data available.");
            return;
        }

        double sum = 0;
        double min = Double.MAX_VALUE;
        double max = Double.MIN_VALUE;

        for (Number val : values) {
            double d = val.doubleValue();
            sum += d;
            if (d < min) min = d;
            if (d > max) max = d;
        }

        double average = sum / values.size();
        System.out.printf("  Count: %d | Min: %.2f | Max: %.2f | Avg: %.2f\n", values.size(), min, max, average);
    }
}
