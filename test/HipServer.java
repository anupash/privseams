import java.net.Socket;
import java.net.ServerSocket;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.io.InputStreamReader;
import jip.HipAddress;
import jip.HipSocketFactory;

public class HipServer {

    public static void main (String[] args) {
	try {
	    ServerSocket.setSocketFactory(new HipSocketFactory());
	    Socket.setSocketImplFactory(new HipSocketFactory());
	    if (args.length < 2) {
		System.err.println("Usage: HipServer <host> <port>");
		System.exit(1);
	    }
	    int port = Integer.parseInt(args[1]);
	    ServerSocket ss =
		new ServerSocket(port, 5, HipAddress.getByName(args[0]));
	    System.out.println(ss.toString());
	    Socket s = ss.accept();
	    System.out.println(s.toString());
	    InputStream is = s.getInputStream();
	    System.out.println(is.toString());
	    BufferedReader in = new BufferedReader(new InputStreamReader(is));
	    OutputStream os = s.getOutputStream();
	    System.out.println(os.toString());
	    PrintWriter out = new PrintWriter(os);
	    String line;
	    while ((line = in.readLine()) != null) {
		out.println(line);
		out.flush();
	    }
	} catch (Exception ex) {
	    ex.printStackTrace();
	}
    }

}
