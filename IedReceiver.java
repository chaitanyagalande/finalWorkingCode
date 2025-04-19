import org.jnetpcap.*;
import org.jnetpcap.packet.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class IedReceiver {
    private static final String NETWORK_INTERFACE_NAME = "\\Device\\NPF_{1C0E2866-2575-4737-BFD3-56BE18394B03}"; // Update as needed
    private static final double CURRENT_THRESHOLD = 15.0; // Current magnitude threshold for GOOSE trigger

    private Pcap pcap;
    private PcapIf networkInterface;
    private GooseSender gooseSender;

    public IedReceiver() throws IOException {
        networkInterface = findNetworkInterface();
        if (networkInterface == null) {
            String error = "No suitable network interface found. Exiting.";
            LoggerSV.log(error);
            System.err.println(error);
            throw new IOException(error);
        }

        pcap = Pcap.openLive(networkInterface.getName(), 65535, Pcap.MODE_PROMISCUOUS, 10_000, new StringBuilder());
        if (pcap == null) {
            String error = "Error opening network interface for capturing packets. Exiting.";
            LoggerSV.log(error);
            System.err.println(error);
            throw new IOException(error);
        }

        // Initialize the GOOSE sender
        try {
            gooseSender = new GooseSender();
        } catch (IOException e) {
            String error = "Failed to initialize GOOSE sender: " + e.getMessage();
            LoggerSV.log(error);
            System.err.println(error);
            throw new IOException(error);
        }

        String msg = "Receiving raw Ethernet frames on interface: " + networkInterface.getName();
        LoggerSV.log(msg);
        System.out.println(msg);
    }

    private void receiveEthernetFrames() {
        pcap.loop(Pcap.LOOP_INFINITE, new PcapPacketHandler<String>() {
            public void nextPacket(PcapPacket packet, String user) {
                if (packet.size() > 14) {
                    int etherType = ((packet.getUByte(12) << 8) | packet.getUByte(13)) & 0xFFFF;
                    System.out.println("EtherType: " + Integer.toHexString(etherType));

                    if (etherType == 0x88BA) { // Custom EtherType for SCADA-like messages
                        byte[] payload = packet.getByteArray(14, packet.size() - 14);
                        String encryptedData = new String(payload).trim();
                        
                        LoggerSV.log("Received encrypted data with hash: " + encryptedData);
                        LoggerSV.log("---------------------------------------------");
                        
                        try {
                            // Decrypt and verify the hash
                            String decryptedData = AESEncryption.decryptAndVerify(encryptedData);
                            
                            if (decryptedData != null) {
                                // Only process data if hash verification was successful
                                LoggerSV.log("Decryption and hash verification successful");
                                LoggerSV.log("Decrypted data:");
                                LoggerSV.log(decryptedData);
                                LoggerSV.log("---------------------------------------------");
                                processAndLogSVData(decryptedData);
                            } else {
                                LoggerSV.log("Hash verification failed - ignoring data");
                            }
                        } catch (Exception e) {
                            LoggerSV.log("Error decrypting data: " + e.getMessage());
                            e.printStackTrace();
                        }
                        LoggerSV.log("===========================================");
                    } else if (etherType == 0x806) { // ARP (EtherType 0x806)
                        LoggerSV.log("Received ARP packet, ignoring.");
                    } else {
                        LoggerSV.log("Ignoring non-SCADA packet with EtherType: " + Integer.toHexString(etherType));
                    }
                } else {
                    String error = "Received malformed Ethernet frame.";
                    LoggerSV.log(error);
                    System.out.println(error);
                }
            }
        }, "SCADA Receiver");
    }

    private void processAndLogSVData(String rawData) {
        // Split by any whitespace
        String[] allValues = rawData.trim().split("\\s+");

        if (allValues.length != 64) {
            LoggerSV.log("Error: Expected 64 values, found " + allValues.length);
            return;
        }

        String[][] matrix = new String[4][16];
        int[] gooseData = new int[16]; // Array to hold GOOSE triggers for each measurement set

        for (int i = 0; i < 64; i++) {
            int row = i / 16;
            int col = i % 16;
            matrix[row][col] = allValues[i];
        }

        LoggerSV.log("Formatted SV Data:");
        for (int set = 0; set < 16; set++) {
            try {
                double vm = Double.parseDouble(matrix[0][set]);
                double va = Double.parseDouble(matrix[1][set]);
                double cm = Double.parseDouble(matrix[2][set]);
                double ca = Double.parseDouble(matrix[3][set]);

                LoggerSV.log(String.format("Measurement Set %d:", set + 1));
                LoggerSV.log(String.format("  Voltage Magnitude: %.11f", vm));
                LoggerSV.log(String.format("  Voltage Angle: %.11f", va));
                LoggerSV.log(String.format("  Current Magnitude: %.11f", cm));
                LoggerSV.log(String.format("  Current Angle: %.11f", ca));
                
                // Check GOOSE trigger condition: If |Current Magnitude| > 15, then trigger GOOSE = 1
                if (Math.abs(cm) > CURRENT_THRESHOLD) {
                    gooseData[set] = 1;
                    LoggerSV.log(String.format("  GOOSE Trigger: 1 (Current magnitude %.11f exceeds threshold %.1f)", 
                                            cm, CURRENT_THRESHOLD));
                } else {
                    gooseData[set] = 0;
                    LoggerSV.log(String.format("  GOOSE Trigger: 0 (Current magnitude %.11f below threshold %.1f)", 
                                            cm, CURRENT_THRESHOLD));
                }
                
            } catch (NumberFormatException e) {
                LoggerSV.log("Error parsing value in Measurement Set " + (set + 1));
                gooseData[set] = 0; // Default to no trigger if parsing error
            }
        }
        
        // Send the GOOSE data through the GooseSender
        if (gooseSender != null) {
            LoggerSV.log("Sending GOOSE triggers to GooseSender...");
            gooseSender.sendGooseMessage(gooseData);
        } else {
            LoggerSV.log("Error: GooseSender not initialized, cannot send GOOSE data");
        }
    }

    private PcapIf findNetworkInterface() throws IOException {
        List<PcapIf> devices = new ArrayList<>();
        StringBuilder errorBuffer = new StringBuilder();

        int result = Pcap.findAllDevs(devices, errorBuffer);
        if (result != Pcap.OK || devices.isEmpty()) {
            String error = "Error finding devices: " + errorBuffer.toString();
            LoggerSV.log(error);
            System.err.println(error);
            throw new IOException("No network devices found.");
        }

        for (PcapIf device : devices) {
            if (device.getName().equals(NETWORK_INTERFACE_NAME)) {
                return device;
            }
        }

        String error = "Specified network interface not found: " + NETWORK_INTERFACE_NAME;
        LoggerSV.log(error);
        System.err.println(error);
        return null;
    }
    
    public void close() {
        if (gooseSender != null) {
            gooseSender.close();
        }
        
        if (pcap != null) {
            pcap.close();
            String msg = "Closed jNetPcap network interface.";
            LoggerSV.log(msg);
            System.out.println(msg);
        }
    }

    public static void main(String[] args) {
        try {
            IedReceiver receiver = new IedReceiver();
            
            // Add shutdown hook to clean up resources
            Runtime.getRuntime().addShutdownHook(new Thread(receiver::close));
            
            receiver.receiveEthernetFrames();
        } catch (IOException e) {
            String error = "Receiver initialization failed: " + e.getMessage();
            LoggerSV.log(error);
            System.err.println(error);
        }
    }
}