/*
 * Author:    Jaakko Kangasharju
 * Copyright: GNU/GPL 2004
 */

package jip;

import java.net.SocketImpl;
import java.net.SocketImplFactory;

/**
 * A socket factory to use for getting HIP sockets.  An application
 * wishing to use HIP needs to install an object of this class as the
 * socket factory to use when creating new sockets.  For any network
 * application this requires code like
 * <pre>
 * HipSocketImplFactory factory = new HipSocketImplFactory();
 * Socket.setSocketImplFactory(factory);
 * </pre>
 * Code using a {@link java.net.ServerSocket} also requires
 * <pre>
 * ServerSocket.setSocketFactory(factory);
 * </pre>
 *
 * @author Jaakko Kangasharju
 */
public class HipSocketImplFactory implements SocketImplFactory {

    public SocketImpl createSocketImpl () {
	return new HipSocketImpl();
    }

}
