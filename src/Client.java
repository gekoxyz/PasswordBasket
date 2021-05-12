import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.io.*;
import java.util.*;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Client {
    private Socket socket;

    private boolean active = true;
    private OutputStream outputStream;
    private ObjectOutputStream objectOutputStream;
    private InputStream inputStream;
    private ObjectInputStream objectInputStream;

    private List<String> messages = new ArrayList<String>();
    private Cipher cipher;
    private String salt = "";

    public Client() {
        try {
            socket = new Socket("127.0.0.1", 10000);
            // -- SEND --
            // get the output stream from the socket.
            outputStream = socket.getOutputStream();
            // create an object output stream from the output stream so we can send an
            // object through it
            objectOutputStream = new ObjectOutputStream(outputStream);
            // -- RECEIVE --
            // get the input stream from the connected socket
            inputStream = socket.getInputStream();
            // create a DataInputStream so we can read data from it.
            objectInputStream = new ObjectInputStream(inputStream);
            // setto il cipher per fare aes ecb senza padding
            cipher = Cipher.getInstance("AES");
        } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            System.out.println(e);
        }
    }

    public static void main(String[] args) {
        Client client = new Client();
        client.run();
    }

    private void run() {
        // conversazione lato client
        Scanner scan = new Scanner(System.in);
        String message = "";
        String username = "";
        String password = "";
        Console console = System.console();
        byte[] vaultKey = null;
        byte[] loginPassword = null;
        SecretKeySpec aesVaultKey = null;
        String preamble = "";
        String inputModifier = "";
        while (active) {
            getServerMessages();
            System.out.println(messages);
            int headerLength = Integer.parseInt(messages.remove(0));
            headerLength--;
            inputModifier = messages.remove(headerLength);
            headerLength--;
            if (headerLength >= 0) {
                preamble = messages.remove(0);
            }
            switch (preamble) {
                case "salt":
                    salt = messages.remove(0);
                    System.out.println("GOT THE SALT " + salt);
                    break;
                case "service_decrypt":
                    // decrypt
                    // setto il cipher in modalita` decrypt

                    // if (i % 2 == 0) {
                    // System.out.print(msg + " -> ");
                    // } else {
                    // // DECRYPTED CIPHER
                    // cipher.init(Cipher.DECRYPT_MODE, aesVaultKey);
                    // System.out.println(cipher.doFinal(hexToBytes(msg)));
                    // }

                    for (int j = 0; j < messages.size(); j++) {
                        if (!messages.get(0).equals("end_decrypt")) {
                            System.out.println(messages.remove(0));
                        } else {
                            messages.remove("end_decrypt");
                            break;
                        }
                    }
                    break;
                default:
                    break;
            }
            for (String msg : messages) {
                System.out.println(msg);
            }
            messages.clear();
            try {
                switch (inputModifier) {
                    case "default":
                        message = scan.nextLine();
                        send(message);
                        break;
                    case "username":
                        username = scan.nextLine();
                        send(username);
                        break;
                    case "password":
                        password = new String(console.readPassword());
                        // hashing vault key + pass to get the login password
                        // hash(vaultKey+pass)
                        // hash(hash(user+pass)+pass)
                        vaultKey = pbkdf2(password + username, salt);
                        System.out.println("[DEBUG] vault key: " + bytesToHex(vaultKey));
                        loginPassword = pbkdf2(bytesToHex(vaultKey) + password, salt);
                        System.out.println("[DEBUG] auth key: " + bytesToHex(loginPassword));
                        aesVaultKey = new SecretKeySpec(vaultKey, "AES");
                        System.out.println("[VAULTKEY] " + bytesToHex(vaultKey));
                        System.out.println("[SECRETKEY] " + aesVaultKey);
                        send(bytesToHex(loginPassword));
                        break;
                    case "service_password":
                        password = new String(console.readPassword());
                        // setto il cipher in modalita` encrypt
                        cipher.init(Cipher.ENCRYPT_MODE, aesVaultKey);
                        String encryptedCipher = bytesToHex(cipher.doFinal(password.getBytes()));
                        // ENCRYPTED CIPHER
                        System.out.println(encryptedCipher);
                        send(encryptedCipher);
                        break;
                    case "no_operation":
                        System.out.println("goodbye!");
                        break;
                    default:
                        break;
                }
            } catch (Exception e) {
                System.out.println("EXCEPTION IO");
            }
            preamble = "";
            inputModifier = "";
        }
    }

    // PBKDF2
    public static byte[] pbkdf2(String password, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 10000, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return f.generateSecret(spec).getEncoded();
    }

    // send message to the server and reset the stream
    private void send(String message) {
        try {
            objectOutputStream.writeObject(message);
            objectOutputStream.reset();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private List<String> getServerMessages() {
        try {
            System.out.println("[DEBUG] waiting for message " + socket);
            messages = (List<String>) objectInputStream.readObject();
            System.out.println("Received [" + (messages.size()) + "] messages from: " + socket);
        } catch (ClassNotFoundException | IOException e) {
            System.out.println("[ERROR] error while receiving messages from the server " + e);
        }
        return messages;
    }

    private static final byte[] HEX_ARRAY = "0123456789abcdef".getBytes(StandardCharsets.US_ASCII);

    public static String bytesToHex(byte[] bytes) {
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }

    public static byte[] hexToBytes(String str) {
        byte[] val = new byte[str.length() / 2];
        for (int i = 0; i < val.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(str.substring(index, index + 2), 16);
            val[i] = (byte) j;
        }
        return val;
    }
}