import java.net.Socket;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;

class ServerThread extends Thread {
    private static Socket socket;

    private static OutputStream outputStream;
    private static ObjectOutputStream objectOutputStream;
    private static InputStream inputStream;
    private static ObjectInputStream objectInputStream;

    private static List<String> messages = new ArrayList<String>();

    public ServerThread(Socket richiestaClient) {
        try {
            socket = richiestaClient;
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
            this.start();
        } catch (IOException e) {
            System.out.println(e);
        }
    }

    public void run() {
        // conversazione lato server
        try {
            System.out.println("[INFO] client connected");
            Connection dbConnection = connectToDatabase();
            System.out.println("[INFO] Database connected");
            boolean active = true;
            while (active) {
                String msg = (String) objectInputStream.readObject();
                // -- SELECT CASE FOR USER LOGIN/REGISTER --
                switch (msg) {
                    case "login":
                        login(dbConnection);
                        break;
                    case "register":
                        register(dbConnection);
                        break;
                    default:
                        break;
                }
            }
        } catch (ClassNotFoundException | IOException | SQLException e) {
            e.printStackTrace();
        }
    }

    private static Connection connectToDatabase() throws SQLException, ClassNotFoundException {
        System.out.println("[INFO] Intializing database connection for user " + socket);
        Class.forName("com.mysql.cj.jdbc.Driver");
        return DriverManager.getConnection("jdbc:mysql://localhost:3306/testmat", "root", "");
    }

    private static void register(Connection dbConnection) {
        System.out.println("[DEBUG] client selected register " + socket);
        messages.add("username");
        messages.add("You selected register");
        messages.add("What username do you want?");
        send(messages);
    }

    private static void login(Connection dbConnection) {
        System.out.println("[DEBUG] client selected login " + socket);
        messages.add("username");
        messages.add("You selected login");
        messages.add("Input your username");
        send(messages);
    }

    // resetto la stream, scrivo l'oggetto e pulisco la lista di messaggi
    private static void send(List<String> messagesToSend){
        System.out.println("[DEBUG] Sending data to " + socket);
        try {
            objectOutputStream.reset();
            objectOutputStream.writeObject(messagesToSend);
            messages.clear();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // convert digest to a string
    private static String hexaToString(byte[] digest) {
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

    // generate random salt for password storing
    private static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[8];
        random.nextBytes(bytes);
        return bytes;
    }
}