import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
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
    private DateTimeFormatter dtf = DateTimeFormatter.ofPattern("HH:mm:ss");

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
            socket = richiestaClient;
            System.out.println(getHour() + " [INFO] " + getSocketAddress() + " connected ");
            dbConnection = connectToDatabase();
            System.out.println(getHour() + " [INFO] " + getSocketAddress() + " database connected");
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
            printErrorMessage("initialization error", e);
        }
    }

    @Override
    public void run() {
        // conversazione lato server
        String command;
        while (active) {
            addHeader(Headers.DEFAULT);
            payload.add("== What action do you want to perform? ==");
            payload.add("1. Login");
            payload.add("2. Register");
            payload.add("3. Credits");
            payload.add("4. Exit");
            send();
            command = getUserInput();
            // -- SELECT CASE FOR USER LOGIN/REGISTER --
            switch (command) {
                case "1":
                    login();
                    break;
                case "2":
                    register();
                    break;
                case "3":
                    payload.add("function not yet implemented");
                    break;
                case "4":
                    addHeader(Headers.NO_OPERATIONS);
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
        System.out.println(getHour() + " [INFO] " + getSocketAddress() + " Intializing database connection");
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            return DriverManager.getConnection("jdbc:mysql://localhost:3306/passwordbasket", "root", "");
        } catch (SQLException | ClassNotFoundException e) {
            printErrorMessage("errore nella connessione al database classnotfound/sql ", e);
            return null;
        }
    }

    // resetto la stream, scrivo l'oggetto e pulisco la lista di messaggi
    private void send() {
        System.out.println(getHour() + " [DEBUG] " + getSocketAddress() + " sending data to client");
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
            printErrorMessage("error occurred while sending message", e);
        }
    }

    private String getUserInput() {
        try {
            return (String) objectInputStream.readObject();
        } catch (ClassNotFoundException | IOException e) {
            printErrorMessage("error while reading String from client", e);
            return null;
        }
    }

    private void register() {
        String usernameToRegister = "";
        String mailToRegister = "";
        boolean invalidMail = true;
        System.out.println(getHour() + " [DEBUG] " + getSocketAddress() + " client selected register");
        payload.add("You selected register");
        addHeader(Headers.MAIL);
        while (invalidMail) {
            payload.add("insert your email");
            send();
            boolean mailExists = checkFieldExistence(dbConnection, "mail");
            if (mailExists) {
                System.out.println(getHour() + " [DEBUG] " + getSocketAddress()
                        + " mail exists, not available for the registration");
                addHeader(Headers.MAIL);
                payload.add("there is already an account associated with this email!");
            } else {
                System.out.println(getHour() + " [DEBUG] " + getSocketAddress()
                        + " mail does not exists, available for the registration");
                mailToRegister = valueToCheck;
                addHeader(Headers.DEFAULT);
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
                System.out.println(getHour() + " [DEBUG] " + getSocketAddress()
                        + " username exists, not available for the registration");
                addHeader(Headers.DEFAULT);
                payload.add("sorry, username is taken :(");
            } else {
                System.out.println(getHour() + " [DEBUG] " + getSocketAddress()
                        + " username does not exists, available for the registration");
                usernameToRegister = valueToCheck;
                addHeader(Headers.SALT);
                salt = Converter.bytesToHex(generateSalt());
                addHeader(salt);
                addHeader(Headers.PASSWORD);
                payload.add("username is not taken yet :)");
                invalidUsername = false;
            }
        }
        System.out.println(
                getHour() + " [DEBUG] " + getSocketAddress() + " username not taken, sending result to the client");
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
            int rowsAffected = preparedStatement.executeUpdate();
            System.out.println(getHour() + " [DEBUG] " + getSocketAddress() + " rows affected: " + rowsAffected);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        addHeader(Headers.DEFAULT);
        payload.add("registration completed!");
        payload.add("type 1 to authenticate");
    }

    private void login() {
        System.out.println(getHour() + " [DEBUG] " + getSocketAddress() + " client selected login");
        addHeader(Headers.DEFAULT);
        payload.add("you selected login");
        invalidUsername = true;
        while (invalidUsername) {
            payload.add("input your username");
            send();
            // getting username
            boolean usernameExists = checkFieldExistence(dbConnection, "username");
            if (!usernameExists) {
                System.out.println(
                        getHour() + " [DEBUG] " + getSocketAddress() + " username doesn't exist, invalid operation");
                addHeader(Headers.DEFAULT);
                payload.add("input username is not valid");
            } else {
                System.out.println(getHour() + " [DEBUG] " + getSocketAddress() + " username exists, valid operation");
                addHeader(Headers.SALT);
                addHeader(salt);
                addHeader(Headers.STORED_MAIL);
                addHeader(mail);
                addHeader(Headers.PASSWORD);
                username = valueToCheck;
                invalidUsername = false;
            }
        }
        // richiesta inserimento password + verifica validita` password
        boolean invalidPassword = true;
        while (invalidPassword) {
            System.out.println(getHour() + " [DEBUG] " + getSocketAddress() + " asking for the password");
            payload.add("input your password");
            send();
            hashedPassword = getHashedPassword();
            System.out.println(getHour() + " [DEBUG] " + getSocketAddress() + " password validation");
            System.out.println(getHour() + " [DEBUG] " + getSocketAddress() + " stored password: " + storedPassword);
            System.out.println(getHour() + " [DEBUG] " + getSocketAddress() + " hashed password: " + hashedPassword);
            if (storedPassword.equals(hashedPassword)) {
                // login is valid
                // messages.add(new Message("valid password!"));
                System.out.println(getHour() + " [DEBUG] " + getSocketAddress() + " valid password");
                addHeader(Headers.DEFAULT);
                invalidPassword = false;
            } else {
                // password invalid
                System.out.println(getHour() + " [DEBUG] " + getSocketAddress() + " invalid password");
                addHeader(Headers.PASSWORD);
                payload.add("invalid password!");
            }
        }
        payload.add("successfully logged in!");
        loggedInOptions();
    }

    private String getHashedPassword() {
        password = getUserInput();
        System.out.println(getHour() + " [DEBUG] " + getSocketAddress() + " password received");
        messageDigest.update((password + salt).getBytes());
        return Converter.bytesToHex(messageDigest.digest());
    }

    private boolean checkFieldExistence(Connection dbConnection, String field) {
        PreparedStatement preparedStatement;
        try {
            valueToCheck = getUserInput();
            System.out.println(getHour() + " [DEBUG] " + getSocketAddress()
                    + " got field to check if it exists in database: " + valueToCheck);
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
            System.out.println("error while checking field existance. field: " + field + " " + e);
            return false;
        }
    }

    private void loggedInOptions() {
        boolean activeLogin = true;
        while (activeLogin) {
            payload.add("== What do you want to do? ==");
            payload.add("1. Register a service");
            payload.add("2. Get the passwords for a service");
            payload.add("3. Remove a service");
            payload.add("4. Logout");
            send();
            String command = getUserInput();
            System.out.println(getHour() + " [INFO] " + getSocketAddress() + " user wants to use service " + command);
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
        addHeader(Headers.DEFAULT);
        payload.add("what service do you want to add?");
        send();
        String service = getUserInput();
        addHeader(Headers.SERVICE_USERNAME);
        payload.add("what's the username for " + service + "?");
        send();
        String serviceUsername = getUserInput();
        addHeader(Headers.SERVICE_PASSWORD);
        payload.add("what's the password for " + serviceUsername + "@" + service + "?");
        send();
        String servicePassword = getUserInput();
        addServiceAccountQuery(service, serviceUsername, servicePassword);
        addHeader(Headers.DEFAULT);
        payload.add("account added successfully!");
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
            System.out.println(getHour() + " [INSERT] " + getSocketAddress() + " inserting " + service + " "
                    + serviceUsername + " " + servicePassword + " " + username);
            rowsAffected = preparedStatement.executeUpdate();
        } catch (SQLException e) {
            printErrorMessage("error while entering the account in the database", e);
        }
        System.out.println(getHour() + " [DEBUG] add service query successful. rows affected:" + rowsAffected);
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
            printErrorMessage("error while getting services for user", e1);
        }
        send();
        return getUserInput();
    }

    private void getServiceAccount() {
        PreparedStatement preparedStatement;
        ResultSet rs;
        addHeader(Headers.DEFAULT);
        payload.add("which service do you want to get the accounts of?");
        String serviceToGet = getServiceToManipulate();
        // select * from users_accounts where service = ? and user = ?
        try {
            preparedStatement = dbConnection
                    .prepareStatement("SELECT * FROM user_accounts WHERE service = ? AND username = ?");
            preparedStatement.setString(1, serviceToGet);
            preparedStatement.setString(2, username);
            System.out.println(
                    getHour() + " [INFO] " + getSocketAddress() + " SELECT * FROM user_accounts WHERE service = '"
                            + serviceToGet + "' AND username = '" + username + "'");
            rs = preparedStatement.executeQuery();
            System.out.println(getHour() + " [INFO] " + getSocketAddress() + " got results. printing to messages");
            addHeader(Headers.SERVICE_DECRYPT);
            while (rs.next()) {
                String serviceUsername = rs.getString("service_username");
                String servicePassword = rs.getString("service_password");
                addHeader(serviceUsername);
                addHeader(servicePassword);
                System.out.println(getHour() + " [INFO] " + getSocketAddress() + " sending to user ");
                System.out.println(getHour() + " [INFO] " + getSocketAddress() + " username:" + serviceUsername);
                System.out.println(getHour() + " [INFO] " + getSocketAddress() + " password:" + servicePassword);
            }
            addHeader(Headers.END_DECRYPT);
            addHeader(Headers.DEFAULT);
        } catch (SQLException e) {
            printErrorMessage("exception while getting service account", e);
        }
    }

    private void deleteServiceAccount() {
        PreparedStatement preparedStatement;
        addHeader(Headers.DEFAULT);
        payload.add("what service do you want to delete the account of?");
        String serviceToDelete = getServiceToManipulate();
        try {
            preparedStatement = dbConnection
                    .prepareStatement("SELECT * FROM user_accounts WHERE service = ? AND username = ?");
            preparedStatement.setString(1, serviceToDelete);
            preparedStatement.setString(2, username);
            ResultSet rs = preparedStatement.executeQuery();
            System.out.println(getHour() + " [INFO] " + getSocketAddress() + " got results. printing to messages");
            addHeader(Headers.USERNAME_DECRYPT);
            addHeader("what " + serviceToDelete + " account do you want to remove? (input account username)");
            while (rs.next()) {
                String serviceUsername = rs.getString("service_username");
                addHeader(serviceUsername);
                System.out.println(getHour() + " [INFO] " + getSocketAddress() + " sending to user ");
                System.out.println(getHour() + " [INFO] " + getSocketAddress() + " username:" + serviceUsername + "@"
                        + serviceToDelete);
            }
            addHeader(Headers.END_DECRYPT);
            addHeader(Headers.SERVICE_USERNAME);
        } catch (SQLException e) {
            printErrorMessage("error while fetching accounts for service for user", e);
        }
        send();
        String accountToDelete = getUserInput();
        System.out.println(getHour() + " [INFO] " + getSocketAddress() + " user wants to remove " + accountToDelete);
        int rowsAffected = 0;
        try {
            preparedStatement = dbConnection.prepareStatement(
                    "DELETE FROM user_accounts WHERE service = ? AND service_username = ? AND username = ?");
            preparedStatement.setString(1, serviceToDelete);
            preparedStatement.setString(2, accountToDelete);
            preparedStatement.setString(3, username);
            rowsAffected = preparedStatement.executeUpdate();
        } catch (SQLException e) {
            printErrorMessage("error while deleting account for user", e);
        }
        System.out.println(getHour() + " [INFO] " + getSocketAddress() + " rows affected: " + rowsAffected);
        addHeader(Headers.DEFAULT);
        payload.add(serviceToDelete + " account removed successfully");
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

    private String getHour() {
        return new String(LocalTime.now().format(dtf));
    }

    private String getSocketAddress() {
        return socket.getInetAddress().getHostAddress() + ":" + socket.getPort();
    }

    private void printErrorMessage(String message, Exception e) {
        System.out.println(getHour() + " [ERROR] " + getSocketAddress() + " " + message + " " + e);
        System.out.println("interrupting thread");
        Thread.currentThread().stop();
    }
}