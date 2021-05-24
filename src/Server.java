import java.net.*;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.io.*;

public class Server {
    private ServerSocket server;

    public Server() {
        try {
            server = new ServerSocket(10000);
            System.out.println(getHour() + " [INFO] server attivo");
        } catch (IOException e) {
            System.out.println(e);
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
            System.out.println(e);
        }
    }

    private String getHour() {
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("HH:mm:ss");
        return new String(LocalTime.now().format(dtf));
    }
}