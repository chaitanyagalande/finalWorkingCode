import org.jnetpcap.*;
import java.util.*;

public class NetworkInterfacesTest {
    public static void main(String[] args) {
        List<PcapIf> devices = new ArrayList<>();
        StringBuilder errorBuffer = new StringBuilder();

        int result = Pcap.findAllDevs(devices, errorBuffer);
        if (result != Pcap.OK || devices.isEmpty()) {
            System.out.println("Error finding devices: " + errorBuffer.toString());
            return;
        }

        System.out.println("Available network interfaces:");
        for (PcapIf device : devices) {
            try {
                System.out.println("Name: " + device.getName());
                System.out.println("Description: " + device.getDescription());
                System.out.println("-------------------------------------------------");
            } catch (Exception e) {
                System.out.println("Error reading device info: " + e.getMessage());
            }
        }
    }
}
