import java.net.*;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.io.*;

public class Server {
    private ServerSocket server;

    public Server() {
        try {
            server = new ServerSocket(10000);
            System.out.println(getHour() + " [INFO] server active on port " + getSocketPort());
        } catch (IOException e) {
            printErrorMessage("error during server initialization", e);
        }
    }

    public static void main(String[] args) {
        Server server = new Server();
        server.run();
    }

    public void run() {
        try {
            while (true) {
                Socket clientRequest = server.accept();
                new Thread(new ServerThread(clientRequest)).start();
            }
        } catch (IOException e) {
            printErrorMessage("error occurred while accepting a new client", e);
        }
    }

    private String getHour() {
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("HH:mm:ss");
        return new String(LocalTime.now().format(dtf));
    }

    private int getSocketPort() {
        return server.getLocalPort();
    }

    private void printErrorMessage(String message, Exception e) {
        System.out.println(getHour() + " [ERROR] " + getSocketPort() + " " + message + " " + e);
        System.out.println("interrupting thread");
    }
}