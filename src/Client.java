import java.net.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
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

    private OutputStream outputStream;
    private ObjectOutputStream objectOutputStream;
    private InputStream inputStream;
    private ObjectInputStream objectInputStream;
    private Scanner scan = new Scanner(System.in);

    private DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss");
    private boolean active = true;
    private Cipher cipher;
    private List<String> messages = new ArrayList<String>();
    private String salt = "";
    private String message = "";
    private String password = "";
    private Console console = System.console();
    private byte[] vaultKey = null;
    private byte[] loginPassword = null;
    private SecretKeySpec aesVaultKey = null;
    private String preamble = "";
    private String inputModifier = "";
    private String mail = "";
    private Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
    private int headerLength;
    private String toEncrypt;

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
        System.out.println("  ____                                     _ ____            _        _   ");
        System.out.println(" |  _ \\ __ _ ___ _____      _____  _ __ __| | __ )  __ _ ___| | _____| |_ ");
        System.out.println(" | |_) / _` / __/ __\\ \\ /\\ / / _ \\| '__/ _` |  _ \\ / _` / __| |/ / _ \\ __|");
        System.out.println(" |  __/ (_| \\__ \\__ \\\\ V  V / (_) | | | (_| | |_) | (_| \\__ \\   <  __/ |_ ");
        System.out.println(" |_|   \\__,_|___/___/ \\_/\\_/ \\___/|_|  \\__,_|____/ \\__,_|___/_|\\_\\___|\\__|");
        System.out.println();
        Client client = new Client();
        client.run();
    }

    private void run() {
        // conversazione lato client
        while (active) {
            getServerMessages();
            handleHeader();
            for (String msg : messages) {
                System.out.println(msg);
            }
            messages.clear();
            handleInputModifier();
        }
    }

    // PBKDF2
    public byte[] pbkdf2(String password, String salt) {
        try {
            KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 10000, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(keySpec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println(getHour() + " [ERROR] " + getSocketAddress() + " error while hashing the password " + e);
            return null;
        }
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
            System.out.println(getHour() + " [INFO] " + getSocketAddress() + " waiting for server message");
            messages = (List<String>) objectInputStream.readObject();
        } catch (ClassNotFoundException | IOException e) {
            System.out.println(getHour() + " [ERROR] " + getSocketAddress()
                    + " error while receiving messages from the server " + e);
        }
        return messages;
    }

    private void handleHeader() {
        headerLength = Integer.parseInt(messages.remove(0));
        headerLength--;
        inputModifier = messages.remove(headerLength);
        while (headerLength > 0) {
            preamble = messages.remove(0);
            headerLength--;
            switch (preamble) {
                case Headers.SALT:
                    salt = messages.remove(0);
                    headerLength--;
                    break;
                case Headers.STORED_MAIL:
                    mail = messages.remove(0);
                    headerLength--;
                    break;
                case Headers.SERVICE_DECRYPT:
                    serviceDecrypt();
                    break;
                case Headers.USERNAME_DECRYPT:
                    usernameDecrypt();
                    break;
                default:
                    break;
            }
        }
    }

    private void serviceDecrypt() {
        try {
            cipher.init(Cipher.DECRYPT_MODE, aesVaultKey);
        } catch (InvalidKeyException e1) {
            System.out.println("invalid decryption initialization");
        }
        int toDecrypt = 0;
        int decryptedPasswordsNumber = 0;
        List<String> decryptedPasswords = new ArrayList<String>();
        try {
            while (!messages.get(0).equals(Headers.END_DECRYPT)) {
                if (toDecrypt % 2 == 0) {
                    decryptedPasswordsNumber++;
                    System.out.print(decryptedPasswordsNumber + ". "
                            + new String(cipher.doFinal(Converter.hexToBytes(messages.remove(0)))) + " -> ");
                } else {
                    decryptedPasswords.add(new String(cipher.doFinal(Converter.hexToBytes(messages.get(0)))));
                    System.out.println(new String(cipher.doFinal(Converter.hexToBytes(messages.remove(0)))));
                }
                toDecrypt++;
                headerLength--;
            }
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("invalid decryption" + e);
        }
        if (decryptedPasswordsNumber == 1) {
            System.out.println("input 1 to copy the password to the clipboard (n to skip)");
        } else {
            System.out.println(
                    "input 1-" + decryptedPasswordsNumber + " to copy a password to the clipboard. (n to skip)");
        }
        String passwordToCopy = scan.nextLine();
        if (!passwordToCopy.equals("n")) {
            StringSelection selection = new StringSelection(
                    decryptedPasswords.get(Integer.parseInt(passwordToCopy) - 1));
            clipboard.setContents(selection, null);
            System.out.println("password copied to the clipboard!");
        } else {
            System.out.println("password not copied to the clipboard!");
        }
    }

    private void usernameDecrypt() {
        System.out.println(messages.remove(0));
        headerLength--;
        try {
            cipher.init(Cipher.DECRYPT_MODE, aesVaultKey);
            while (!messages.get(0).equals(Headers.END_DECRYPT)) {
                System.out.println(new String(cipher.doFinal(Converter.hexToBytes(messages.remove(0)))));
                headerLength--;
            }
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("invalid decryption initialization");
        }
        headerLength--;
        messages.remove(0);
    }

    private void handleInputModifier() {
        try {
            switch (inputModifier) {
                case Headers.DEFAULT:
                    message = scan.nextLine();
                    send(message);
                    break;
                case Headers.MAIL:
                    mail = scan.nextLine();
                    send(mail);
                    break;
                case Headers.PASSWORD:
                    insertPassword();
                    break;
                case Headers.ENCRYPTED_DATA:
                    toEncrypt = scan.nextLine();
                    encryptData(toEncrypt);
                    break;
                case Headers.SERVICE_PASSWORD:
                    insertServicePassword();
                    break;
                case Headers.NO_OPERATIONS:
                    System.out.println("goodbye!");
                    break;
                default:
                    break;
            }
        } catch (Exception e) {
            System.out.println(getHour() + " [ERROR] " + getSocketAddress() + " IO exception");
        }
        inputModifier = "";
    }

    private void insertPassword() {
        password = new String(console.readPassword());
        // hashing vault key + pass to get the login password
        // hash(vaultKey+pass)
        // hash(hash(user+pass)+pass)
        vaultKey = pbkdf2(password + mail, salt);
        System.out.println(
                getHour() + " [DEBUG] " + getSocketAddress() + " vault key: " + Converter.bytesToHex(vaultKey));
        loginPassword = pbkdf2(Converter.bytesToHex(vaultKey) + password, salt);
        System.out.println(
                getHour() + " [DEBUG] " + getSocketAddress() + " auth key: " + Converter.bytesToHex(loginPassword));
        aesVaultKey = new SecretKeySpec(vaultKey, "AES");
        System.out.println(getHour() + " [SECRETKEY] " + getSocketAddress() + " " + aesVaultKey);
        send(Converter.bytesToHex(loginPassword));
    }

    private void encryptData(String toEncrypt) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, aesVaultKey);
            String encryptedCipher = Converter.bytesToHex(cipher.doFinal(toEncrypt.getBytes()));
            send(encryptedCipher);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            System.out
                    .println(getHour() + " [ERROR] " + getSocketAddress() + " error while encrypting service password");
        }
    }

    private void insertServicePassword() {
        System.out.println("do you want to use a randomly generated password? (y/n)");
        if (scan.nextLine().equals("y")) {
            password = PasswordGenerator.generateRandomPassword();
            System.out.println("generated the random password: " + password);
        } else {
            System.out.print("input your password: ");
            password = new String(console.readPassword());
        }
        encryptData(password);
    }

    private String getHour() {
        return new String(LocalTime.now().format(dateTimeFormatter));
    }

    private String getSocketAddress() {
        return socket.getInetAddress().getHostAddress() + ":" + socket.getLocalPort();
    }
}