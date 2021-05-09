import java.net.*;
import java.io.*;

public class Server {
    private ServerSocket server;

    public Server() {
        try {
            server = new ServerSocket(10000);
            System.out.println("[INFO] server attivo");
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
}