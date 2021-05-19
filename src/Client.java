import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.io.*;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Clipboard;
import java.awt.Toolkit;
import java.util.Scanner;

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
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        while (active) {
            getServerMessages();
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
                    try {
                        cipher.init(Cipher.DECRYPT_MODE, aesVaultKey);
                    } catch (InvalidKeyException e1) {
                        System.out.println("invalid decryption initialization");
                    }
                    int i = 0;
                    int j = 0;
                    List<String> decryptedPasswords = new ArrayList<String>();
                    try {
                        while (!messages.get(0).equals("end_decrypt")) {
                            if (i % 2 == 0) {
                                j++;
                                decryptedPasswords.add(messages.get(0));
                                System.out.print(j + ". " + messages.remove(0) + " -> ");
                            } else {
                                decryptedPasswords.add(new String(cipher.doFinal(hexToBytes(messages.get(0)))));
                                System.out.println(new String(cipher.doFinal(hexToBytes(messages.remove(0)))));
                            }
                            i++;
                        }
                    } catch (IllegalBlockSizeException | BadPaddingException e) {
                        System.out.println("invalid decryption" + e);
                    }
                    if (j == 1) {
                        System.out.println("input 1 to copy the password to the clipboard (n to skip)");
                    } else {
                        System.out.println("input 1-" + j + " to copy a password to the clipboard. (n to skip)");
                    }
                    String passwordToCopy = scan.nextLine();
                    if (!passwordToCopy.equals("n")) {
                        StringSelection selection = new StringSelection(
                                decryptedPasswords.get(Integer.parseInt(passwordToCopy)));
                        clipboard.setContents(selection, null);
                        System.out.println("password copied to the clipboard!");
                    } else {
                        System.out.println("password not copied to the clipboard!");
                    }
                    messages.remove(0);
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
                        System.out.println("[SECRETKEY] " + aesVaultKey);
                        send(bytesToHex(loginPassword));
                        break;
                    case "service_password":
                        System.out.println("do you want to use a randomly generated password? (y/n)");
                        if (scan.nextLine().equals("y")) {
                            password = PasswordGenerator.generateRandomPassword();
                            System.out.println("generated the random password: " + password);
                        } else {
                            System.out.print("input your password: ");
                            password = new String(console.readPassword());
                        }
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