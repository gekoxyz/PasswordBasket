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
    private Socket socket;

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
    private String service = "";

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
        boolean active = true;
        while (active) {
            System.out.println("[DEBUG] current socket: " + socket);
            String msg = receiveString();
            System.out.println("[CLIENT] " + msg);
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
            objectOutputStream.flush();
            messages.clear();
        } catch (IOException e) {
            System.out.println("[ERROR] error occurred while sending message");
        }
    }

    private String receiveString() {
        try {
            return (String) objectInputStream.readObject();
        } catch (ClassNotFoundException | IOException e) {
            System.out.println("[ERROR] error while reading String from client");
        }
        return "";
    }

    private void register(Connection dbConnection) {
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
        messages.add("Input the password");
        send(messages);
        // get password
        // TODO: PUT PASSWORD REQUEST PART IN SEPARATE METHOD
        password = receiveString();
        System.out.println("[DEBUG] got password request");
        // hashing the password, generating a random salt and saving it to the database
        // to finally secure login credentials
        salt = hexaToString(generateSalt());
        messageDigest.update((password + salt).getBytes());
        hashedPassword = hexaToString(messageDigest.digest());
        try {
            // preparing insert query and executing it
            PreparedStatement preparedStatement = dbConnection
                    .prepareStatement("INSERT INTO users_login (username, password, salt) VALUES (?, ?, ?)");
            preparedStatement.setString(1, username);
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
            password = receiveString();
            System.out.println("[DEBUG] password received");
            messageDigest.update((password + salt).getBytes());
            hashedPassword = hexaToString(messageDigest.digest());
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
        // password validata, richiesta di inserimento/lettura/modifica/cancellazione
        // password
        boolean loggedIn = true;
        while (loggedIn) {
            messages.add("Logged in succesfully!");
            messages.add("What action do you want to perform?");
            messages.add("1. Input account");
            messages.add("2. Get service accounts");
            messages.add("3. Remove account");
            send(messages);
            String command = receiveString();
            System.out.println("[DEBUG] user input: " + command);
            messages.add("default");
            switch (command) {
                case "1":
                    // needings : service, service username, service password
                    // GETTING SERVICE
                    messages.add("What service do you want to save?");
                    send(messages);
                    service = receiveString();
                    System.out.println("[DEBUG] user wants to add service " + service);
                    // GETTING USERNAME FOR SERVICE
                    messages.add("username");
                    messages.add("What's the username for: " + service + "?");
                    send(messages);
                    String serviceUsername = receiveString();
                    System.out.println("[DEBUG] username of service is " + serviceUsername);
                    // GETTING PASSWORD FOR SERVICE
                    messages.add("service_password");
                    messages.add("What's the password for " + serviceUsername + "?");
                    send(messages);
                    String servicePassword = receiveString();
                    System.out.println("[DEBUG] service password is " + servicePassword);
                    // insert data in database
                    // INSERT INTO `users_accounts` (`service`, `service_username`,
                    // `service_password`, `user`) VALUES ('SERVICE', 'SERVICEUSERNAME',
                    // 'SERVICEPASSWORD', 'matteo')
                    PreparedStatement preparedStatement;
                    try {
                        preparedStatement = dbConnection.prepareStatement(
                                "INSERT INTO users_accounts (service, service_username, service_password, user) VALUES (?, ?, ?, ?)");
                        preparedStatement.setString(1, service);
                        preparedStatement.setString(2, serviceUsername);
                        preparedStatement.setString(3, servicePassword);
                        preparedStatement.setString(4, username);
                        int rowsAffected = preparedStatement.executeUpdate();
                        System.out.println("[DEBUG] rows affected:" + rowsAffected);
                    } catch (SQLException e) {
                        e.printStackTrace();
                    }
                    break;
                case "2":
                    // needings: service name
                    // GETTING SERVICE
                    messages.add("What service do you want to know the account of?");
                    send(messages);
                    service = receiveString();
                    System.out.println("[DEBUG] user wants to get accounts of service " + service);
                    try {
                        preparedStatement = dbConnection
                                .prepareStatement("SELECT * FROM users_accounts WHERE service = ? AND user = ?;");
                        preparedStatement.setString(1, service);
                        preparedStatement.setString(2, username);
                        ResultSet rs = preparedStatement.executeQuery();
                        // TODO: mettere tutto nell'arraylist di messaggi e inviare tutto al client
                        if (!rs.next()) {
                            // non ci sono account per questo servizio o hai fatto casino non lo so devo
                            // testare
                        } else {
                            String storedUsername = rs.getString("service_username");
                            String storedPassword = rs.getString("service_password");
                            messages.add("accounts");
                            messages.add(storedUsername);
                            messages.add(storedPassword);
                            // storedPassword = rs.getString("password");
                            // salt = rs.getString("salt");
                            // metto i dati degli account nei messaggi e li invio al client
                        }
                    } catch (SQLException e) {
                        e.printStackTrace();
                    }
                    break;
                case "3":
                    messages.add("delete account");
                    send(messages);
                    // needings: service name
                    break;
                default:
                    break;
            }
        }

    }

    // check if username exists in database
    private boolean checkUsernameExistence(Connection dbConnection) {
        String username;
        try {
            username = receiveString();
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
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    // convert digest to a string
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

    // generate random salt for password storing
    private byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[8];
        random.nextBytes(bytes);
        return bytes;
    }
}