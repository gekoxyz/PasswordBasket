import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;

class ServerThread implements Runnable {
    private static Socket socket;

    private static Connection dbConnection;
    private static OutputStream outputStream;
    private static ObjectOutputStream objectOutputStream;
    private static InputStream inputStream;
    private static ObjectInputStream objectInputStream;

    private static List<String> messages = new ArrayList<String>();
    private static MessageDigest messageDigest;

    // private static String username = "";
    // private static String password = "";
    private static String salt = "";
    // private static String hashedPassword = "";
    private static boolean invalidUsername;
    private static String storedPassword = "";
    // private static String service = "";

    public ServerThread(Socket richiestaClient) {
        try {
            socket = richiestaClient;
            System.out.println("[INFO] " + socket + " connected ");
            dbConnection = connectToDatabase();
            System.out.println("[INFO] Database connected");
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
            // non puo` uscire un NoSuchAlgorithmException perche` so che l'algoritmo esiste
            // ed e` cosi` definito
            System.out.println("[ERROR] errore di i/o");
        } catch (SQLException | ClassNotFoundException e) {
            System.out.println("[ERROR] errore nella connessione al database classnotfound/sql " + e);
        }
    }

    public void run() {
        // conversazione lato server
        try {
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
        } catch (IOException | ClassNotFoundException e) {
            System.out.println("[ERROR] errore nello switch azioni ioexception " + e);
        }
    }

    private static Connection connectToDatabase() throws SQLException, ClassNotFoundException {
        System.out.println("[INFO] Intializing database connection");
        Class.forName("com.mysql.cj.jdbc.Driver");
        return DriverManager.getConnection("jdbc:mysql://localhost:3306/testmat", "root", "");
    }

    private static void register(Connection dbConnection) {
        System.out.println("[DEBUG] client selected register " + socket);
        messages.add("username");
        messages.add("You selected register");
        invalidUsername = true;
        while (invalidUsername) {
            messages.add("input the username you want");
            send(messages);
            // getting username
            boolean usernameExists = checkUsernameExistence(dbConnection);
            if (usernameExists) {
                System.out.println("[DEBUG] username exists, not available for the registration");
                messages.add("username");
                messages.add("sorry, username is taken :(");
            } else {
                System.out.println("[DEBUG] username does not exists, available for the registration");
                messages.add("password");
                messages.add("username is not taken yet :)");
                invalidUsername = false;
            }
        }
        System.out.println("[DEBUG] username not taken, sending result to " + socket);
        // messages.add("Input the password");
        // send(messages);
        // // get password
        // // TODO: PUT PASSWORD REQUEST PART IN SEPARATE METHOD
        // try {
        // password = (String) objectInputStream.readObject();
        // } catch (ClassNotFoundException | IOException e) {
        // e.printStackTrace();
        // }
        // System.out.println("[DEBUG] got password request");
        // // hashing the password, generating a random salt and saving it to the
        // database
        // // to finally secure login credentials
        // salt = hexaToString(generateSalt());
        // messageDigest.update((password + salt).getBytes());
        // hashedPassword = hexaToString(messageDigest.digest());
        // try {
        // // preparing insert query and executing it
        // PreparedStatement preparedStatement = dbConnection.prepareStatement("INSERT
        // INTO users_login (username, password, salt) VALUES (?, ?, ?)");
        // preparedStatement.setString(1, username);
        // preparedStatement.setString(2, hashedPassword);
        // preparedStatement.setString(3, salt);
        // // TODO: if rows affected = 0 throw login error
        // int rowsAffected = preparedStatement.executeUpdate();
        // System.out.println("[DEBUG] rows affected: " + rowsAffected);
        // } catch (SQLException e) {
        // e.printStackTrace();
        // }
        // messages.add("default");
        // messages.add("registration completed!");
        // messages.add("type login to authenticate");
        // send(messages);
    }

    private static void login(Connection dbConnection) {
        System.out.println("[DEBUG] client selected login " + socket);
        messages.add("username");
        messages.add("You selected login");
        messages.add("Input your username");
        send(messages);
    }

    // resetto la stream, scrivo l'oggetto e pulisco la lista di messaggi
    private static void send(List<String> messagesToSend) {
        System.out.println("[DEBUG] Sending data to " + socket);
        try {
            objectOutputStream.writeObject(messagesToSend);
            objectOutputStream.flush();
            messages.clear();
        } catch (IOException e) {
            System.out.println("[ERROR] error occurred while sending message");
        }
    }

    // check if username exists in database
    private static boolean checkUsernameExistence(Connection dbConnection) {
        String username;
        try {
            username = (String) objectInputStream.readObject();
            System.out.println("[DEBUG] got username for login");
            PreparedStatement preparedStatement = dbConnection
                    .prepareStatement("SELECT * FROM users_login WHERE username = ?");
            preparedStatement.setString(1, username);
            ResultSet rs = preparedStatement.executeQuery();
            if (!rs.next()) {
                return false;
            } else {
                storedPassword = rs.getString("password");
                salt = rs.getString("salt");
                return true;
            }
        } catch (ClassNotFoundException | IOException | SQLException e) {
            e.printStackTrace();
            return false;
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