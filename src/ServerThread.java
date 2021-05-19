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
import java.util.List;
import java.util.Set;
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

    private List<String> payload = new ArrayList<String>();
    private List<String> header = new ArrayList<String>();
    private int headerLength = 0;
    private MessageDigest messageDigest;

    private String username = "";
    private String password = "";
    private String salt = "";
    private String hashedPassword = "";
    private boolean invalidUsername;
    private String storedPassword = "";

    public ServerThread(Socket richiestaClient) {
        try {
            // aggiungere messaggi cosi` formattati: 2015-11-10 15:26:57 4348 [Note] Server
            // socket created on IP: '::'.
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
            addHeader("default");
            payload.add("== Cosa vuoi fare? ==");
            payload.add("1. Login");
            payload.add("2. Register");
            payload.add("3. Credits");
            payload.add("4. Exit");
            send();
            command = getUserInput();
            // -- SELECT CASE FOR USER LOGIN/REGISTER --
            switch (command) {
                case "1":
                    login(dbConnection);
                    break;
                case "2":
                    register(dbConnection);
                    break;
                case "3":
                    payload.add("function not yet implemented");
                    break;
                case "4":
                    addHeader("no_operation");
                    send();
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
    private void send() {
        System.out.println("[DEBUG] Sending data to " + socket);
        try {
            header.add(0, Integer.toString(headerLength));
            header.addAll(payload);
            // System.out.println(header);
            objectOutputStream.writeObject(header);
            objectOutputStream.reset();
            payload.clear();
            header.clear();
            headerLength = 0;
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
        addHeader("username");
        payload.add("You selected register");
        invalidUsername = true;
        while (invalidUsername) {
            payload.add("input the username you want");
            send();
            // getting username
            boolean usernameExists = checkUsernameExistence(dbConnection);
            if (usernameExists) {
                System.out.println("[DEBUG] username exists, not available for the registration");
                addHeader("username");
                payload.add("sorry, username is taken :(");
            } else {
                System.out.println("[DEBUG] username does not exists, available for the registration");
                usernameToRegister = username;
                addHeader("salt");
                salt = bytesToHex(generateSalt());
                addHeader(salt);
                addHeader("password");
                payload.add("username is not taken yet :)");
                invalidUsername = false;
            }
        }
        System.out.println("[DEBUG] username not taken, sending result to " + socket);
        payload.add("Input the password");
        send();
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
        addHeader("default");
        payload.add("registration completed!");
        payload.add("type 1 to authenticate");
    }

    private void login(Connection dbConnection) {
        System.out.println("[DEBUG] client selected login " + socket);
        addHeader("username");
        payload.add("you selected login");
        invalidUsername = true;
        while (invalidUsername) {
            payload.add("input your username");
            send();
            // getting username
            boolean usernameExists = checkUsernameExistence(dbConnection);
            if (!usernameExists) {
                System.out.println("[DEBUG] username doesn't exist, invalid operation");
                addHeader("username");
                payload.add("input username is not valid");
            } else {
                System.out.println("[DEBUG] username exists, valid operation");
                addHeader("salt");
                addHeader(salt);
                addHeader("password");
                invalidUsername = false;
            }
        }
        // richiesta inserimento password + verifica validita` password
        boolean invalidPassword = true;
        while (invalidPassword) {
            System.out.println("[DEBUG] asking for the password");
            payload.add("input your password");
            send();
            password = getUserInput();
            System.out.println("[DEBUG] password received");
            messageDigest.update((password + salt).getBytes());
            hashedPassword = bytesToHex(messageDigest.digest());
            System.out.println("[DEBUG] password validation");
            System.out.println("stored password: " + storedPassword);
            System.out.println("hashed password: " + hashedPassword);
            if (storedPassword.equals(hashedPassword)) {
                // login is valid
                // messages.add(new Message("valid password!"));
                System.out.println("[DEBUG] valid password");
                addHeader("default");
                invalidPassword = false;
            } else {
                // password invalid
                System.out.println("[DEBUG] invalid password");
                addHeader("password");
                payload.add("invalid password!");
            }
        }
        payload.add("successfully logged in!");
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
            payload.add("what do you want to do?");
            payload.add("1. Register a service");
            payload.add("2. Get the passwords for a service");
            payload.add("3. Remove a service");
            payload.add("4. Logout");
            send();
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
        addHeader("default");
        payload.add("what service do you want to add?");
        send();
        String service = getUserInput();
        addHeader("default");
        payload.add("what's the username for " + service + "?");
        send();
        String serviceUsername = getUserInput();
        addHeader("service_password");
        payload.add("what's the password for " + serviceUsername + "@" + service + "?");
        send();
        String servicePassword = getUserInput();
        addServiceAccountQuery(service, serviceUsername, servicePassword);
        addHeader("default");
        payload.add("account aggiunto con successo");
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
        addHeader("default");
        payload.add("which service do you want to get the accounts of?");
        send();
        // TODO: show the users all of his accounts
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
            addHeader("service_decrypt");
            while (rs.next()) {
                String serviceUsername = rs.getString("service_username");
                String servicePassword = rs.getString("service_password");
                payload.add(serviceUsername);
                payload.add(servicePassword);
                System.out.println("[INFO] sending to user ");
                System.out.println("username:" + serviceUsername);
                System.out.println("password:" + servicePassword);
            }
            payload.add("end_decrypt");
            addHeader("default");
        } catch (SQLException e) {
            System.out.println("[ERROR] exception while getting service account " + e);
        }
    }

    private void deleteServiceAccount() {
        int rowsAffected = 0;
        addHeader("default");
        payload.add("what service do you want to delete the account of?");
        send();
        String service = getUserInput();
        PreparedStatement preparedStatement;
        try {
            preparedStatement = dbConnection
                    .prepareStatement("SELECT * FROM users_accounts WHERE service = ? AND user = ?");
            preparedStatement.setString(1, service);
            preparedStatement.setString(2, username);
            ResultSet rs = preparedStatement.executeQuery();
            System.out.println("[INFO] got results. printing to messages");
            addHeader("default");
            payload.add("what " + service + " account do you want to remove? (input account username)");
            while (rs.next()) {
                String serviceUsername = rs.getString("service_username");
                payload.add(serviceUsername);
                System.out.println("[INFO] sending to user ");
                System.out.println("username:" + serviceUsername + "@" + service);
            }
        } catch (SQLException e) {
            System.out.println("[ERROR] error while fetching accounts for service for user " + e);
        }
        send();
        String accountToRemove = getUserInput();
        System.out.println("[INFO] user wants to remove " + accountToRemove);
        try {
            preparedStatement = dbConnection.prepareStatement(
                    "DELETE FROM users_accounts WHERE service = ? AND service_username = ? AND user = ?");
            preparedStatement.setString(1, service);
            preparedStatement.setString(2, accountToRemove);
            preparedStatement.setString(3, username);
            rowsAffected = preparedStatement.executeUpdate();
        } catch (SQLException e) {
            System.out.println("[ERROR] error while deleting account for user " + e);
        }
        /*
         * DELETE FROM users_accounts WHERE service = ? AND service_username = ?
         */
        System.out.println("[INFO] rows affected: " + rowsAffected);
        addHeader("default");
        payload.add("account " + accountToRemove + "@" + service + " removed successfully");
    }

    // generate random salt for password storing
    private byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[8];
        random.nextBytes(bytes);
        return bytes;
    }

    private static final Set<String> PREAMBLES = Set.of("salt", "service_decrypt");
    // private static final Set<String> INPUT_MODIFIERS = Set.of("default",
    // "username", "password", "service_password");

    private void addHeader(String option) {
        headerLength++;
        if (PREAMBLES.contains(option)) {
            header.add(0, option);
        } else {
            header.add(option);
        }
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