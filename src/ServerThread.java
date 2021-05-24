import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
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

    private List<String> payload = new ArrayList<String>();
    private List<String> header = new ArrayList<String>();
    private int headerLength = 0;
    private MessageDigest messageDigest;

    private String username = "";
    private String password = "";
    private String salt = "";
    private String mail = "";
    private String hashedPassword = "";
    private boolean invalidUsername;
    private String storedPassword = "";
    private String valueToCheck = "";

    public ServerThread(Socket richiestaClient) {
        try {
            // aggiungere messaggi cosi` formattati: 2015-11-10 15:26:57 4348 [Note] Server
            // socket created on IP: '::'.
            socket = richiestaClient;
            System.out.println(
                    printHour() + " [INFO] " + socket.getLocalAddress() + ":" + socket.getLocalPort() + " connected ");
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
            connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/passwordbasket", "root", "");
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
        String mailToRegister = "";
        boolean invalidMail = true;
        System.out.println("[DEBUG] client selected register " + socket);
        payload.add("You selected register");
        addHeader("mail");
        while (invalidMail) {
            payload.add("insert your email");
            send();
            boolean mailExists = checkFieldExistence(dbConnection, "mail");
            if (mailExists) {
                System.out.println("[DEBUG] mail exists, not available for the registration");
                addHeader("mail");
                payload.add("there is already an account associated with this email!");
            } else {
                System.out.println("[DEBUG] mail does not exists, available for the registration");
                mailToRegister = valueToCheck;
                addHeader("username");
                payload.add("valid mail!");
                invalidMail = false;
            }
        }
        invalidUsername = true;
        while (invalidUsername) {
            payload.add("input the username you want");
            send();
            // getting username
            boolean usernameExists = checkFieldExistence(dbConnection, "username");
            if (usernameExists) {
                System.out.println("[DEBUG] username exists, not available for the registration");
                addHeader("username");
                payload.add("sorry, username is taken :(");
            } else {
                System.out.println("[DEBUG] username does not exists, available for the registration");
                usernameToRegister = valueToCheck;
                addHeader("salt");
                salt = Converter.bytesToHex(generateSalt());
                addHeader(salt);
                addHeader("password");
                payload.add("username is not taken yet :)");
                invalidUsername = false;
            }
        }
        System.out.println("[DEBUG] username not taken, sending result to " + socket);
        payload.add("Input the password");
        send();
        // get password and hash it
        hashedPassword = getHashedPassword();
        try {
            // preparing insert query and executing it
            PreparedStatement preparedStatement = dbConnection.prepareStatement(
                    "INSERT INTO user_login (username, password, salt, name, mail) VALUES (?, ?, ?, NULL, ?)");
            preparedStatement.setString(1, usernameToRegister);
            preparedStatement.setString(2, hashedPassword);
            preparedStatement.setString(3, salt);
            // name
            preparedStatement.setString(4, mailToRegister);
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
            boolean usernameExists = checkFieldExistence(dbConnection, "username");
            if (!usernameExists) {
                System.out.println("[DEBUG] username doesn't exist, invalid operation");
                addHeader("username");
                payload.add("input username is not valid");
            } else {
                System.out.println("[DEBUG] username exists, valid operation");
                addHeader("salt");
                addHeader(salt);
                addHeader("stored_mail");
                addHeader(mail);
                addHeader("password");
                username = valueToCheck;
                invalidUsername = false;
            }
        }
        // richiesta inserimento password + verifica validita` password
        boolean invalidPassword = true;
        while (invalidPassword) {
            System.out.println("[DEBUG] asking for the password");
            payload.add("input your password");
            send();
            hashedPassword = getHashedPassword();
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

    private String getHashedPassword() {
        password = getUserInput();
        System.out.println("[DEBUG] password received");
        messageDigest.update((password + salt).getBytes());
        return Converter.bytesToHex(messageDigest.digest());
    }

    private boolean checkFieldExistence(Connection dbConnection, String field) {
        PreparedStatement preparedStatement;
        try {
            valueToCheck = getUserInput();
            System.out.println("[DEBUG] got field to check if it exists in database: " + valueToCheck);
            preparedStatement = dbConnection.prepareStatement("SELECT * FROM user_login WHERE " + field + " = ?");
            preparedStatement.setString(1, valueToCheck);
            ResultSet rs = preparedStatement.executeQuery();
            if (!rs.next()) {
                return false;
            } else {
                storedPassword = rs.getString("password");
                salt = rs.getString("salt");
                mail = rs.getString("mail");
                return true;
            }
        } catch (SQLException e) {
            System.out.println("ERROR WHILE CHECKING FIELD EXISTANCE. FIELD: " + field + " " + e);
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
                    getServiceAccount();
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
                    "INSERT INTO user_accounts (service, service_username, service_password, username) VALUES (?, ?, ?, ?)");
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

    private String getServiceToManipulate() {
        PreparedStatement preparedStatement;
        ResultSet rs;
        try {
            preparedStatement = dbConnection
                    .prepareStatement("SELECT service FROM user_accounts WHERE username = ? GROUP BY service");
            preparedStatement.setString(1, username);
            rs = preparedStatement.executeQuery();
            while (rs.next()) {
                String service = rs.getString("service");
                payload.add(service);
            }
        } catch (SQLException e1) {
            System.out.println("[ERROR] error while getting services for user " + e1);
        }
        send();
        return getUserInput();
    }

    private void getServiceAccount() {
        PreparedStatement preparedStatement;
        ResultSet rs;
        addHeader("default");
        payload.add("which service do you want to get the accounts of?");
        String serviceToGet = getServiceToManipulate();
        // select * from users_accounts where service = ? and user = ?
        try {
            preparedStatement = dbConnection
                    .prepareStatement("SELECT * FROM user_accounts WHERE service = ? AND username = ?");
            preparedStatement.setString(1, serviceToGet);
            preparedStatement.setString(2, username);
            System.out.println("SELECT * FROM user_accounts WHERE service = '" + serviceToGet + "' AND username = '"
                    + username + "'");
            rs = preparedStatement.executeQuery();
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
        PreparedStatement preparedStatement;
        addHeader("default");
        payload.add("what service do you want to delete the account of?");
        String serviceToDelete = getServiceToManipulate();
        try {
            preparedStatement = dbConnection
                    .prepareStatement("SELECT * FROM user_accounts WHERE service = ? AND username = ?");
            preparedStatement.setString(1, serviceToDelete);
            preparedStatement.setString(2, username);
            ResultSet rs = preparedStatement.executeQuery();
            System.out.println("[INFO] got results. printing to messages");
            addHeader("default");
            payload.add("what " + serviceToDelete + " account do you want to remove? (input account username)");
            while (rs.next()) {
                String serviceUsername = rs.getString("service_username");
                payload.add(serviceUsername);
                System.out.println("[INFO] sending to user ");
                System.out.println("username:" + serviceUsername + "@" + serviceToDelete);
            }
        } catch (SQLException e) {
            System.out.println("[ERROR] error while fetching accounts for service for user " + e);
        }
        send();
        String accountToDelete = getUserInput();
        System.out.println("[INFO] user wants to remove " + accountToDelete);
        int rowsAffected = 0;
        try {
            preparedStatement = dbConnection.prepareStatement(
                    "DELETE FROM user_accounts WHERE service = ? AND service_username = ? AND username = ?");
            preparedStatement.setString(1, serviceToDelete);
            preparedStatement.setString(2, accountToDelete);
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
        payload.add("account " + accountToDelete + "@" + serviceToDelete + " removed successfully");
    }

    // generate random salt for password storing
    private byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[8];
        random.nextBytes(bytes);
        return bytes;
    }

    private void addHeader(String option) {
        headerLength++;
        header.add(option);
    }

    private static String printHour() {
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("HH:mm:ss");
        return new String(LocalTime.now().format(dtf));
    }
}