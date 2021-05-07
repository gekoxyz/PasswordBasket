import java.net.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.*;
import java.util.*;

public class Client {
    private static Socket socket;

    private static OutputStream outputStream;
    private static ObjectOutputStream objectOutputStream;
    private static InputStream inputStream;
    private static ObjectInputStream objectInputStream;

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

    public void conversazione() {
        // conversazione lato client
        Scanner scan = new Scanner(System.in);
        String command = "default";
        String message = "";
        String username = "";
        String password = "";
        Console console = System.console();
        byte[] vaultKey = null;
        List<String> messages = new ArrayList<String>();
        System.out.println("what do you want to do? (login/register)");
        while (true) {
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
                        messageDigest.update((username + password).getBytes());
                        vaultKey = messageDigest.digest();
                        System.out.println("[DEBUG] first digest: " + hexaToString(vaultKey));
                        messageDigest.update((hexaToString(vaultKey) + password).getBytes());
                        byte[] loginPassword = messageDigest.digest();
                        System.out.println("[DEBUG] final digest: " + hexaToString(loginPassword));
                        send(hexaToString(loginPassword));
                        break;
                    default:
                        break;
                }
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

    // send message to the server and reset the stream
    public static void send(String message) {
        try {
            objectOutputStream.writeObject(message);
            objectOutputStream.reset();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Convert digest to a string
    public static String hexaToString(byte[] digest) {
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
    public static String bytesToHexa(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}