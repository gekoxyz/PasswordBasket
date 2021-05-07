import java.net.*;
import java.io.*;

public class Server extends Thread {
    private ServerSocket server;

    public Server() {
        try {
            server = new ServerSocket(10000);
            System.out.println("Server attivo");
            this.start();
        } catch (IOException e) {
            System.out.println(e);
        }
    }

    public void run() {
        try {
            while (true) {
                Socket clientRequest = server.accept();
                new ServerThread(clientRequest);
            }
        } catch (IOException e) {
            System.out.println(e);
        }
    }
}