import org.jnetpcap.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.util.*;

public class GooseSender {
    private static final String GOOSE_MAC_ADDRESS = "00:11:22:33:44:66"; // Different MAC for GOOSE messages
    private static final String NETWORK_INTERFACE_NAME = "\\Device\\NPF_{1C0E2866-2575-4737-BFD3-56BE18394B03}"; // Same as IED

    private Pcap pcap;
    private PcapIf networkInterface;

    public GooseSender() throws IOException {
        networkInterface = findNetworkInterface();
        if (networkInterface == null) {
            String error = "No suitable network interface found for GOOSE sender. Exiting.";
            LoggerGoose.log(error);
            System.err.println(error);
            throw new IOException(error);
        }

        byte[] srcMac = networkInterface.getHardwareAddress();
        if (srcMac == null || srcMac.length != 6) {
            String error = "Could not retrieve valid source MAC address for GOOSE sender.";
            LoggerGoose.log(error);
            throw new IOException(error);
        }

        pcap = Pcap.openLive(networkInterface.getName(), 65535, Pcap.MODE_PROMISCUOUS, 10_000, new StringBuilder());
        if (pcap == null) {
            String error = "Error opening network interface for sending GOOSE packets. Exiting.";
            LoggerGoose.log(error);
            System.err.println(error);
            throw new IOException(error);
        }

        String msg = "GOOSE sender initialized on interface: " + networkInterface.getName();
        LoggerGoose.log(msg);
        System.out.println(msg);
    }

    private void sendEthernetFrame(String data) throws IOException {
        byte[] dataBytes = data.getBytes();

        int minFrameSize = 64;
        int frameSize = Math.max(minFrameSize, 14 + dataBytes.length);

        ByteBuffer buffer = ByteBuffer.allocate(frameSize);

        buffer.put(parseMacAddress(GOOSE_MAC_ADDRESS)); // Destination MAC
        buffer.put(networkInterface.getHardwareAddress()); // Source MAC
        buffer.putShort((short) 0x88B8); // EtherType for GOOSE (0x88B8)

        buffer.put(dataBytes);

        while (buffer.position() < minFrameSize) {
            buffer.put((byte) 0);
        }

        byte[] ethernetFrame = buffer.array();
        pcap.sendPacket(ethernetFrame);
        
        // Log the sent data with detailed information
        LoggerGoose.log("---------------------------------------------");
        LoggerGoose.log("Encrypted GOOSE data with hash (being sent): " + data);
        LoggerGoose.log("---------------------------------------------");
        LoggerGoose.log("Sent GOOSE Ethernet frame size: " + ethernetFrame.length + " bytes");
        LoggerGoose.log("===========================================");
    }

    public void sendGooseMessage(int[] gooseData) {
        try {
            // Convert the gooseData array to a string
            StringBuilder gooseDataStr = new StringBuilder();
            for (int i = 0; i < gooseData.length; i++) {
                gooseDataStr.append(gooseData[i]);
                if (i < gooseData.length - 1) {
                    gooseDataStr.append(" ");
                }
            }
            
            String gooseDataString = gooseDataStr.toString();
            
            // Encrypt the data and append the hash
            String encryptedWithHash = AESEncryption.encryptAndHash(gooseDataString);
            LoggerGoose.log("Original GOOSE data: " + gooseDataString);
            LoggerGoose.log("Original GOOSE data size: " + gooseDataString.length() + " bytes");
            LoggerGoose.log("Encrypted GOOSE data with hash size: " + encryptedWithHash.length() + " bytes");
            
            // Send the encrypted data with the hash
            sendEthernetFrame(encryptedWithHash);
            
        } catch (Exception e) {
            LoggerGoose.log("Error encrypting or sending GOOSE data: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private PcapIf findNetworkInterface() throws IOException {
        List<PcapIf> devices = new ArrayList<>();
        StringBuilder errorBuffer = new StringBuilder();
        int result = Pcap.findAllDevs(devices, errorBuffer);
        if (result != Pcap.OK) {
            String error = "Error finding devices for GOOSE sender: " + errorBuffer.toString();
            LoggerGoose.log(error);
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
            String msg = "Closed jNetPcap network interface for GOOSE sender.";
            LoggerGoose.log(msg);
            System.out.println(msg);
        }
    }
}