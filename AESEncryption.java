import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESEncryption {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    
    // Pre-shared key (in a real system, this would be securely stored)
    // Must be exactly 32 bytes (256 bits) for AES-256
    private static final byte[] PRE_SHARED_KEY = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    
    /**
     * Encrypts the data using AES-256 in GCM mode
     */
    public static String encrypt(String data) throws Exception {
        // Generate a random IV (Initialization Vector)
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        
        // Create the secret key
        SecretKey secretKey = new SecretKeySpec(PRE_SHARED_KEY, "AES");
        
        // Initialize the cipher
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        
        // Encrypt the data
        byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        
        // Combine IV and encrypted data
        byte[] combined = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encryptedData, 0, combined, iv.length, encryptedData.length);
        
        // Return as base64
        return Base64.getEncoder().encodeToString(combined);
    }
    
    /**
     * Decrypts the data using AES-256 in GCM mode
     */
    public static String decrypt(String encryptedData) throws Exception {
        // Decode from base64
        byte[] combined = Base64.getDecoder().decode(encryptedData);
        
        // Extract IV and encrypted data
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] encrypted = new byte[combined.length - GCM_IV_LENGTH];
        
        System.arraycopy(combined, 0, iv, 0, iv.length);
        System.arraycopy(combined, iv.length, encrypted, 0, encrypted.length);
        
        // Create the secret key
        SecretKey secretKey = new SecretKeySpec(PRE_SHARED_KEY, "AES");
        
        // Initialize the cipher for decryption
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
        
        // Decrypt and return
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, StandardCharsets.UTF_8);
    }
    
    /**
     * Calculates SHA-256 hash of the data
     */
    public static String calculateHash(String data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }
    
    /**
     * Converts bytes to hexadecimal string
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
    
    /**
     * Encrypt data and append the hash
     */
    public static String encryptAndHash(String data) throws Exception {
        String hash = calculateHash(data);
        String encrypted = encrypt(data);
        return encrypted + "#" + hash;
    }
    
    /**
     * Decrypt data and verify the hash
     * Returns the decrypted data if hash verification succeeds, null otherwise
     */
    public static String decryptAndVerify(String encryptedWithHash) throws Exception {
        String[] parts = encryptedWithHash.split("#");
        if (parts.length != 2) {
            LoggerSV.log("Invalid encrypted format - missing hash separator");
            return null;
        }
        
        String encrypted = parts[0];
        String receivedHash = parts[1];
        
        String decrypted = decrypt(encrypted);
        String calculatedHash = calculateHash(decrypted);
        
        if (calculatedHash.equals(receivedHash)) {
            LoggerSV.log("Hash verification successful");
            return decrypted;
        } else {
            LoggerSV.log("Hash verification failed - data may be compromised");
            return null;
        }
    }
    
    /**
     * Alternative method to create a key from a password string
     * This is less secure than using a true random key but can be useful for testing
     */
    public static byte[] createKeyFromPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(password.getBytes(StandardCharsets.UTF_8));
    }
}