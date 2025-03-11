import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

public class AdvancedAntivirus {
    
    // List of known malicious signatures (e.g., strings or patterns)
    private static final List<String> MALICIOUS_SIGNATURES = Arrays.asList(
            "malware_signature_1",
            "virus_payload",
            "trojan_code"
    );

    // List of known malicious file hashes (SHA-256)
    private static final Set<String> MALICIOUS_HASHES = new HashSet<>(Arrays.asList(
            "5d41402abc4b2a76b9719d911017c592",  // Example hash
            "098f6bcd4621d373cade4e832627b4f6"   // Example hash
    ));

    public static void main(String[] args) {
        String directoryPath = "C:\\Users"; // Change this path as needed
        String quarantinePath = "C:\\Users"; // Folder to move infected files
        
        System.out.println("Scanning directory: " + directoryPath);
        scanDirectory(directoryPath, quarantinePath);
    }

    public static void scanDirectory(String directoryPath, String quarantinePath) {
        File directory = new File(directoryPath);
        if (!directory.exists() || !directory.isDirectory()) {
            System.out.println("Invalid directory!");
            return;
        }

        File[] files = directory.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isFile()) {
                    scanFile(file, quarantinePath);
                }
            }
        }
    }

    public static void scanFile(File file, String quarantinePath) {
        try {
            String fileHash = getFileChecksum(file);
            System.out.println("Scanning: " + file.getName() + " [SHA-256: " + fileHash + "]");

            // Check for hash-based detection
            if (MALICIOUS_HASHES.contains(fileHash)) {
                System.out.println("Threat found! (Hash-based detection) -> " + file.getName());
                quarantineFile(file, quarantinePath);
                return;
            }

            // Check for signature-based detection
            if (checkSignatures(file)) {
                System.out.println("Threat found! (Signature-based detection) -> " + file.getName());
                quarantineFile(file, quarantinePath);
                return;
            }

            // If we reach here, no threats were found
            System.out.println("No threats found in file: " + file.getName());

        } catch (Exception e) {
            System.out.println("Error scanning file: " + file.getName());
        }
    }

    public static boolean checkSignatures(File file) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                for (String signature : MALICIOUS_SIGNATURES) {
                    if (line.contains(signature)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public static String getFileChecksum(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream fis = new FileInputStream(file);
             DigestInputStream dis = new DigestInputStream(fis, digest)) {
            while (dis.read() != -1); // Read file to compute hash
        }
        byte[] hashBytes = digest.digest();
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashBytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    public static void quarantineFile(File file, String quarantinePath) {
        File quarantineDir = new File(quarantinePath);
        if (!quarantineDir.exists()) {
            quarantineDir.mkdirs();
        }
        File newFile = new File(quarantineDir, file.getName());
        if (file.renameTo(newFile)) {
            System.out.println("File moved to quarantine: " + newFile.getAbsolutePath());
        } else {
            System.out.println("Failed to quarantine file: " + file.getName());
        }
    }
}
