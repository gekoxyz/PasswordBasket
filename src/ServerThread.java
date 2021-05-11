import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;

class ServerThread implements Runnable {
    private Socket socket;

    private boolean active = true;
    private Connection dbConnection = null;
    private OutputStream outputStream;
    private ObjectOutputStream objectOutputStream;
    private InputStream inputStream;
    private ObjectInputStream objectInputStream;

    private List<String> messages = new ArrayList<String>();
    private MessageDigest messageDigest;

    private String username = "";
    private String password = "";
    private String salt = "";
    private String hashedPassword = "";
    private boolean invalidUsername;
    private String storedPassword = "";

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
        }
    }

    public void run() {
        // conversazione lato server
        String command;
        while (active) {
            messages.add("== Cosa vuoi fare? ==");
            messages.add("1. Login");
            messages.add("2. Register");
            messages.add("3. Credits");
            messages.add("4. Exit");
            send(messages);
            command = getUserInput();
            // -- SELECT CASE FOR USER LOGIN/REGISTER --
            switch (command) {
                case "1":
                    login(dbConnection);
                    messages.add("default");
                    break;
                case "2":
                    register(dbConnection);
                    messages.add("default");
                    break;
                case "3":
                    messages.add("default");
                    messages.add("function not yet implemented");
                    break;
                case "4":
                    messages.add("no_operation");
                    send(messages);
                    active = false;
                    break;
                default:
                    break;
            }
        }

    }

    // connessione al database
    private Connection connectToDatabase() {
        Connection connection = null;
        System.out.println("[INFO] Intializing database connection");
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/testmat", "root", "");
        } catch (SQLException | ClassNotFoundException e) {
            System.out.println("[ERROR] errore nella connessione al database classnotfound/sql " + e);
        }
        return connection;
    }

    // resetto la stream, scrivo l'oggetto e pulisco la lista di messaggi
    private void send(List<String> messagesToSend) {
        System.out.println("[DEBUG] Sending data to " + socket);
        try {
            objectOutputStream.writeObject(messagesToSend);
            objectOutputStream.reset();
            messages.clear();
        } catch (IOException e) {
            System.out.println("[ERROR] error occurred while sending message");
        }
    }

    private String getUserInput() {
        try {
            return (String) objectInputStream.readObject();
        } catch (ClassNotFoundException | IOException e) {
            System.out.println("[ERROR] error while reading String from client");
            active = false;
        }
        return "";
    }

    private void register(Connection dbConnection) {
        String usernameToRegister = "";
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
                usernameToRegister = username;
                messages.add("salt");
                salt = bytesToHex(generateSalt());
                messages.add(salt);
                messages.add("password");
                messages.add("username is not taken yet :)");
                invalidUsername = false;
            }
        }
        System.out.println("[DEBUG] username not taken, sending result to " + socket);
        messages.add("Input the password");
        send(messages);
        // get password
        // TODO: PUT PASSWORD REQUEST PART IN SEPARATE METHOD
        password = getUserInput();
        System.out.println("[DEBUG] got password request");
        // hashing the password, generating a random salt and saving it to the database
        // to finally secure login credentials
        messageDigest.update((password + salt).getBytes());
        hashedPassword = bytesToHex(messageDigest.digest());
        try {
            // preparing insert query and executing it
            PreparedStatement preparedStatement = dbConnection
                    .prepareStatement("INSERT INTO users_login (username, password, salt) VALUES (?, ?, ?)");
            preparedStatement.setString(1, usernameToRegister);
            preparedStatement.setString(2, hashedPassword);
            preparedStatement.setString(3, salt);
            // TODO: if rows affected = 0 throw login error
            int rowsAffected = preparedStatement.executeUpdate();
            System.out.println("[DEBUG] rows affected: " + rowsAffected);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        messages.add("default");
        messages.add("registration completed!");
        messages.add("type login to authenticate");
        send(messages);
    }

    private void login(Connection dbConnection) {
        System.out.println("[DEBUG] client selected login " + socket);
        messages.add("username");
        messages.add("you selected login");
        invalidUsername = true;
        while (invalidUsername) {
            messages.add("input your username");
            send(messages);
            // getting username
            boolean usernameExists = checkUsernameExistence(dbConnection);
            if (!usernameExists) {
                System.out.println("[DEBUG] username doesn't exist, invalid operation");
                messages.add("username");
                messages.add("input username is not valid");
            } else {
                System.out.println("[DEBUG] username exists, valid operation");
                messages.add("salt");
                messages.add(salt);
                messages.add("password");
                invalidUsername = false;
            }
        }
        // richiesta inserimento password + verifica validita` password
        boolean invalidPassword = true;
        while (invalidPassword) {
            System.out.println("[DEBUG] asking for the password");
            messages.add("input your password");
            send(messages);
            password = getUserInput();
            System.out.println("[DEBUG] password received");
            messageDigest.update((password + salt).getBytes());
            hashedPassword = bytesToHex(messageDigest.digest());
            System.out.println("[DEBUG] password validation");
            if (storedPassword.equals(hashedPassword)) {
                // login is valid
                // messages.add(new Message("valid password!"));
                System.out.println("[DEBUG] valid password");
                messages.add("default");
                invalidPassword = false;
            } else {
                // password invalid
                System.out.println("[DEBUG] invalid password");
                messages.add("password");
                messages.add("invalid password!");
            }
        }
        messages.add("successfully logged in!");
        loggedInOptions();
    }

    // check if username exists in database
    private boolean checkUsernameExistence(Connection dbConnection) {
        try {
            username = getUserInput();
            System.out.println("[DEBUG] got username to check if it exists in database");
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
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    private void loggedInOptions() {
        boolean activeLogin = true;
        while (activeLogin) {
            messages.add("what do you want to do?");
            messages.add("1. Register a service");
            messages.add("2. Get the passwords for a service");
            messages.add("3. Remove a service");
            messages.add("4. Logout");
            send(messages);
            String command = getUserInput();
            System.out.println("[INFO] user wants to use service " + command);
            switch (command) {
                case "1":
                    // user wants to register a service
                    addServiceAccount();
                    break;
                case "2":
                    // user wants to retreive a service's accounts
                    getServiceAccounts();
                    break;
                case "3":
                    // user wants to remove a service
                    deleteServiceAccount();
                    break;
                case "4":
                    activeLogin = false;
                    break;
                default:
                    break;
            }
        }
    }

    private void addServiceAccount() {
        messages.add("default");
        messages.add("what service do you want to add?");
        send(messages);
        String service = getUserInput();
        messages.add("default");
        messages.add("what's the username for " + service + "?");
        send(messages);
        String serviceUsername = getUserInput();
        messages.add("service_password");
        messages.add("what's the password for " + serviceUsername + "@" + service + "?");
        send(messages);
        String servicePassword = getUserInput();
        addServiceAccountQuery(service, serviceUsername, servicePassword);
        messages.add("default");
        messages.add("account aggiunto con successo");
        send(messages);
    }

    private void addServiceAccountQuery(String service, String serviceUsername, String servicePassword) {
        int rowsAffected = 0;
        try {
            PreparedStatement preparedStatement = dbConnection.prepareStatement(
                    "INSERT INTO users_accounts (service, service_username, service_password, user) VALUES (?, ?, ?, ?)");
            preparedStatement.setString(1, service);
            preparedStatement.setString(2, serviceUsername);
            preparedStatement.setString(3, servicePassword);
            preparedStatement.setString(4, username);
            System.out.println(
                    "[INSERT] inserting " + service + " " + serviceUsername + " " + servicePassword + " " + username);
            rowsAffected = preparedStatement.executeUpdate();
        } catch (SQLException e) {
            System.out.println("[ERROR] error while entering the account in the database");
        }
        System.out.println("[DEBUG] add service query successful. rows affected:" + rowsAffected);
    }

    private void getServiceAccounts() {
        messages.add("default");
        messages.add("which service do you want to get the accounts of?");
        send(messages);
        String service = getUserInput();
        // select * from users_accounts where service = ? and user = ?
        try {
            PreparedStatement preparedStatement = dbConnection
                    .prepareStatement("SELECT * FROM users_accounts WHERE service = ? AND user = ?");
            preparedStatement.setString(1, service);
            preparedStatement.setString(2, username);
            System.out.println(
                    "SELECT * FROM users_accounts WHERE service = '" + service + "' AND user = '" + username + "'");
            ResultSet rs = preparedStatement.executeQuery();
            System.out.println("[INFO] got results. printing to messages");
            messages.add("service_decrypt");
            while (rs.next()) {
                String serviceUsername = rs.getString("service_username");
                String servicePassword = rs.getString("service_password");
                messages.add(serviceUsername);
                messages.add(servicePassword);
                System.out.println("[INFO] sending to user ");
                System.out.println("username:" + serviceUsername);
                System.out.println("password:" + servicePassword);
            }
            messages.add("end_decrypt");
            messages.add("default");
        } catch (SQLException e) {
            System.out.println("[ERROR] exception while getting service account " + e);
        }
    }

    private void deleteServiceAccount() {
    }

    // generate random salt for password storing
    private byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[8];
        random.nextBytes(bytes);
        return bytes;
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