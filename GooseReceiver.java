import org.jnetpcap.*;
import org.jnetpcap.packet.*;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class GooseReceiver {
    private static final String NETWORK_INTERFACE_NAME = "\\Device\\NPF_{1C0E2866-2575-4737-BFD3-56BE18394B03}"; // Same as IED
    private static final String GOOSE_LOG_FILE = "GooseLogs.txt";

    private Pcap pcap;
    private PcapIf networkInterface;

    public GooseReceiver() throws IOException {
        networkInterface = findNetworkInterface();
        if (networkInterface == null) {
            String error = "No suitable network interface found for GOOSE receiver. Exiting.";
            logGooseEvent(error);
            System.err.println(error);
            throw new IOException(error);
        }

        pcap = Pcap.openLive(networkInterface.getName(), 65535, Pcap.MODE_PROMISCUOUS, 10_000, new StringBuilder());
        if (pcap == null) {
            String error = "Error opening network interface for capturing GOOSE packets. Exiting.";
            logGooseEvent(error);
            System.err.println(error);
            throw new IOException(error);
        }

        String msg = "GOOSE receiver initialized on interface: " + networkInterface.getName();
        logGooseEvent(msg);
        System.out.println(msg);
    }

    public void receiveGooseMessages() {
        pcap.loop(Pcap.LOOP_INFINITE, new PcapPacketHandler<String>() {
            public void nextPacket(PcapPacket packet, String user) {
                if (packet.size() > 14) {
                    int etherType = ((packet.getUByte(12) << 8) | packet.getUByte(13)) & 0xFFFF;

                    if (etherType == 0x88B8) { // EtherType for GOOSE (0x88B8)
                        byte[] payload = packet.getByteArray(14, packet.size() - 14);
                        String encryptedData = new String(payload).trim();
                        
                        LoggerGoose.log("Received encrypted GOOSE data with hash: " + encryptedData);
                        LoggerGoose.log("---------------------------------------------");
                        
                        try {
                            // Decrypt and verify the hash
                            String decryptedData = AESEncryption.decryptAndVerify(encryptedData);
                            
                            if (decryptedData != null) {
                                // Only process data if hash verification was successful
                                LoggerGoose.log("Decryption and hash verification successful for GOOSE data");
                                LoggerGoose.log("Decrypted GOOSE data: " + decryptedData);
                                LoggerGoose.log("---------------------------------------------");
                                processGooseData(decryptedData);
                            } else {
                                LoggerGoose.log("Hash verification failed for GOOSE data - ignoring");
                            }
                        } catch (Exception e) {
                            LoggerGoose.log("Error decrypting GOOSE data: " + e.getMessage());
                            e.printStackTrace();
                        }
                        LoggerGoose.log("===========================================");
                    }
                }
            }
        }, "GOOSE Receiver");
    }

    private void processGooseData(String gooseDataStr) {
        try {
            String[] gooseValues = gooseDataStr.trim().split("\\s+");
            
            for (int i = 0; i < gooseValues.length; i++) {
                int gooseValue = Integer.parseInt(gooseValues[i]);
                if (gooseValue == 1) {
                    String message = "GOOSE event triggered at Measurement Set " + (i + 1);
                    logGooseEvent(message);
                    LoggerGoose.log(message);
                }
            }
        } catch (NumberFormatException e) {
            String error = "Error parsing GOOSE data: " + e.getMessage();
            logGooseEvent(error);
            LoggerGoose.log(error);
        }
    }

    private void logGooseEvent(String message) {
        try (FileWriter writer = new FileWriter(GOOSE_LOG_FILE, true)) {
            String timestamp = java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            writer.write("[" + timestamp + "] " + message + "\n");
        } catch (IOException e) {
            e.printStackTrace();
            LoggerGoose.log("Error writing to GOOSE log file: " + e.getMessage());
        }
    }

    private PcapIf findNetworkInterface() throws IOException {
        List<PcapIf> devices = new ArrayList<>();
        StringBuilder errorBuffer = new StringBuilder();

        int result = Pcap.findAllDevs(devices, errorBuffer);
        if (result != Pcap.OK || devices.isEmpty()) {
            String error = "Error finding devices for GOOSE receiver: " + errorBuffer.toString();
            logGooseEvent(error);
            System.err.println(error);
            throw new IOException("No network devices found for GOOSE receiver.");
        }

        for (PcapIf device : devices) {
            if (device.getName().equals(NETWORK_INTERFACE_NAME)) {
                return device;
            }
        }

        String error = "Specified network interface not found for GOOSE receiver: " + NETWORK_INTERFACE_NAME;
        logGooseEvent(error);
        System.err.println(error);
        return null;
    }

    public void close() {
        if (pcap != null) {
            pcap.close();
            String msg = "Closed jNetPcap network interface for GOOSE receiver.";
            logGooseEvent(msg);
            LoggerGoose.log(msg);
        }
    }

    public static void main(String[] args) {
        try {
            GooseReceiver receiver = new GooseReceiver();
            
            Runtime.getRuntime().addShutdownHook(new Thread(receiver::close));
            
            receiver.receiveGooseMessages();
        } catch (IOException e) {
            String error = "GOOSE receiver initialization failed: " + e.getMessage();
            LoggerGoose.log(error);
            System.err.println(error);
        }
    }
}