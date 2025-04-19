import org.jnetpcap.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.util.*;

public class IedSender {
    private static final String SCADA_MAC_ADDRESS = "00:11:22:33:44:55"; // Update as needed
    private static final String NETWORK_INTERFACE_NAME = "\\Device\\NPF_{1C0E2866-2575-4737-BFD3-56BE18394B03}"; // Update as needed
    private static final int DELAY_MS = 1000; // Delay between packets in milliseconds

    private Pcap pcap;
    private PcapIf networkInterface;

    public IedSender() throws IOException {
        networkInterface = findNetworkInterface();
        if (networkInterface == null) {
            String error = "No suitable network interface found. Exiting.";
            LoggerSV.log(error);
            System.err.println(error);
            throw new IOException(error);
        }

        byte[] srcMac = networkInterface.getHardwareAddress();
        if (srcMac == null || srcMac.length != 6) {
            String error = "Could not retrieve valid source MAC address.";
            LoggerSV.log(error);
            throw new IOException(error);
        }

        pcap = Pcap.openLive(networkInterface.getName(), 65535, Pcap.MODE_PROMISCUOUS, 10_000, new StringBuilder());
        if (pcap == null) {
            String error = "Error opening network interface for sending packets. Exiting.";
            LoggerSV.log(error);
            System.err.println(error);
            throw new IOException(error);
        }

        String msg = "Sending raw Ethernet frames on interface: " + networkInterface.getName();
        LoggerSV.log(msg);
        System.out.println(msg);
    }

    private void sendEthernetFrame(String data, String originalData) throws IOException {
        byte[] dataBytes = data.getBytes();

        int minFrameSize = 64;
        int frameSize = Math.max(minFrameSize, 14 + dataBytes.length);

        ByteBuffer buffer = ByteBuffer.allocate(frameSize);

        buffer.put(parseMacAddress(SCADA_MAC_ADDRESS)); // Destination MAC
        buffer.put(networkInterface.getHardwareAddress()); // Source MAC
        buffer.putShort((short) 0x88BA); // EtherType for Sampled Values (SV)

        buffer.put(dataBytes);

        while (buffer.position() < minFrameSize) {
            buffer.put((byte) 0);
        }

        byte[] ethernetFrame = buffer.array();
        pcap.sendPacket(ethernetFrame);
        
        // Log the sent data with detailed information
        LoggerSV.log("---------------------------------------------");
        LoggerSV.log("Encrypted data with hash (being sent): " + data);
        LoggerSV.log("---------------------------------------------");
        LoggerSV.log("Sent Ethernet frame size: " + ethernetFrame.length + " bytes");
        LoggerSV.log("===========================================");
    }

    public void sendSVMessages() throws IOException, InterruptedException {
        String originalData = readSVData("SVdata.txt");
        LoggerSV.log("Loaded SV data from file:");
        LoggerSV.log(originalData);
        
        while (true) {
            try {
                // Encrypt the data and append the hash
                String encryptedWithHash = AESEncryption.encryptAndHash(originalData);
                LoggerSV.log("Original data size: " + originalData.length() + " bytes");
                LoggerSV.log("Encrypted data with hash size: " + encryptedWithHash.length() + " bytes");
                
                // Send the encrypted data with the hash, passing original data for logging
                sendEthernetFrame(encryptedWithHash, originalData);
                
                Thread.sleep(DELAY_MS);
            } catch (Exception e) {
                LoggerSV.log("Error encrypting or sending data: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    private String readSVData(String filename) throws IOException {
        StringBuilder data = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = reader.readLine()) != null) {
                data.append(line.trim()).append(" ");
            }
        }
        return data.toString().trim();
    }

    private PcapIf findNetworkInterface() throws IOException {
        List<PcapIf> devices = new ArrayList<>();
        StringBuilder errorBuffer = new StringBuilder();
        int result = Pcap.findAllDevs(devices, errorBuffer);
        if (result != Pcap.OK) {
            String error = "Error finding devices: " + errorBuffer.toString();
            LoggerSV.log(error);
            return null;
        }

        for (PcapIf device : devices) {
            if (device.getName().equals(NETWORK_INTERFACE_NAME)) {
                return device;
            }
        }
        return null;
    }

    private byte[] parseMacAddress(String macAddress) {
        String[] macAddressParts = macAddress.split(":");
        byte[] macBytes = new byte[6];
        for (int i = 0; i < macAddressParts.length; i++) {
            macBytes[i] = (byte) Integer.parseInt(macAddressParts[i], 16);
        }
        return macBytes;
    }

    public void close() {
        if (pcap != null) {
            pcap.close();
            String msg = "Closed jNetPcap network interface.";
            LoggerSV.log(msg);
            System.out.println(msg);
        }
    }

    public static void main(String[] args) {
        try {
            IedSender sender = new IedSender();

            Thread svThread = new Thread(() -> {
                try {
                    sender.sendSVMessages();
                } catch (IOException | InterruptedException e) {
                    LoggerSV.log("Error in sender thread: " + e.getMessage());
                    e.printStackTrace();
                }
            });

            svThread.start();

            Runtime.getRuntime().addShutdownHook(new Thread(sender::close));

        } catch (IOException e) {
            String error = "Error in IedSender initialization: " + e.getMessage();
            LoggerSV.log(error);
            System.err.println(error);
            e.printStackTrace();
        }
    }
}