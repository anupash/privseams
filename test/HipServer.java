import java.net.Socket;
import java.net.ServerSocket;
import java.net.InetSocketAddress;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.io.InputStreamReader;
import javax.net.ServerSocketFactory;
import jip.HipSocketImplFactory;
import jip.HipServerSocketFactory;

public class HipServer {

    public static void main (String[] args) {
	try {
	    // begin GLOB
	    //ServerSocket.setSocketFactory(new HipSocketImplFactory());
	    //Socket.setSocketImplFactory(new HipSocketImplFactory());
	    // end GLOB
	    // begin PC
	    ServerSocketFactory hipFactory = new HipServerSocketFactory();
	    // end PC
	    if (args.length != 1) {
		System.err.println("Usage: HipServer <port>");
		System.exit(1);
	    }
	    int port = Integer.parseInt(args[0]);
	    // begin GLOB
	    //ServerSocket ss = new ServerSocket();
	    // end GLOB
	    // begin PC
	    ServerSocket ss = hipFactory.createServerSocket();
	    // end PC
	    ss.bind(new InetSocketAddress("", port));
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
