import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;

public class FileEncryptionDecryption {

    private static final String AES_ALGORITHM = "AES";
    private static final String ENCRYPTED_FILE_EXTENSION = ".enc";

    public static void main(String[] args) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {
            System.out.print("Enter file path: ");
            String filePath = reader.readLine();

            System.out.print("Enter encryption key: ");
            String encryptionKey = reader.readLine();

            System.out.print("Encrypt (E) or Decrypt (D): ");
            String mode = reader.readLine();

            if (mode.equalsIgnoreCase("E")) {
                processFile(filePath, encryptionKey, Cipher.ENCRYPT_MODE);
                System.out.println("File encrypted successfully!");
            } else if (mode.equalsIgnoreCase("D")) {
                processFile(filePath, encryptionKey, Cipher.DECRYPT_MODE);
                System.out.println("File decrypted successfully!");
            } else {
                System.out.println("Invalid mode selected.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void processFile(String filePath, String encryptionKey, int cipherMode) throws Exception {
        byte[] fileContent = Files.readAllBytes(Paths.get(filePath));
        Key key = new SecretKeySpec(encryptionKey.getBytes(), AES_ALGORITHM);
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(cipherMode, key);

        byte[] processedContent = cipher.doFinal(fileContent);

        String outputFilePath = cipherMode == Cipher.ENCRYPT_MODE
                ? filePath + ENCRYPTED_FILE_EXTENSION
                : filePath.replace(ENCRYPTED_FILE_EXTENSION, "");
        try (FileOutputStream outputStream = new FileOutputStream(outputFilePath)) {
            outputStream.write(processedContent);
        }
    }
}
