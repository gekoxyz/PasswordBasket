import java.net.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.io.*;
import java.util.*;

import javax.crypto.Cipher;
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

    MessageDigest messageDigest;

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
            // define MessageDigest class algorithm
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (IOException | NoSuchAlgorithmException e) {
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
        String command = "default";
        String message = "";
        String username = "";
        String password = "";
        Console console = System.console();
        byte[] vaultKey = null;
        byte[] loginPassword = null;
        List<String> messages = new ArrayList<String>();
        System.out.println("what do you want to do? (login/register)");
        while (active) {
            try {
                switch (command) {
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
                        vaultKey = pbkdf2(password + username);
                        System.out.println("[DEBUG] vault key: " + bytesToHexa(vaultKey));
                        loginPassword = pbkdf2(bytesToHexa(vaultKey) + password);
                        System.out.println("[DEBUG] auth key: " + bytesToHexa(loginPassword));
                        send(bytesToHexa(loginPassword));
                        break;
                    case "service_password":
                        password = new String(console.readPassword());
                        // get key and encrypt
                        SecretKeySpec secretKey = new SecretKeySpec(vaultKey, "AES");
                        System.out.println("[KEY] " + bytesToHexa(vaultKey));
                        // setto il cipher per fare aes ecb senza padding
                        Cipher cipher = Cipher.getInstance("AES");
                        // setto il cipher in modalita` encrypt
                        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                        String encryptedCipher = Base64.getEncoder()
                                .encodeToString(cipher.doFinal(password.getBytes()));
                        // ENCRYPTED CIPHER
                        System.out.println(encryptedCipher);
                        // send
                        send(encryptedCipher);
                        // cipher.init(Cipher.DECRYPT_MODE, secretKey);
                        // // DECRYPTED CIPHER
                        // System.out.println(new
                        // String(cipher.doFinal(Base64.getDecoder().decode(encryptedCipher))));
                        break;
                    default:
                        break;
                }
                System.out.println("[DEBUG] waiting for message " + socket);
                messages = (List<String>) objectInputStream.readObject();
                System.out.println("Received [" + (messages.size() - 1) + "] messages from: " + socket);
                command = messages.get(0);
                messages.remove(0);
                for (String msg : messages) {
                    System.out.println(msg);
                }
                messages.clear();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    // PBKDF2
    public static byte[] pbkdf2(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String salt = "SALT";
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

    // Convert digest to a string
    private String hexaToString(byte[] digest) {
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < digest.length; i++) {
            if ((0xff & digest[i]) < 0x10) {
                hexString.append("0" + Integer.toHexString((0xFF & digest[i])));
            } else {
                hexString.append(Integer.toHexString(0xFF & digest[i]));
            }
        }
        return hexString.toString();
    }

    // Convert byte array to hexadecimal
    private String bytesToHexa(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}