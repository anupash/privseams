/*
 * Author:    Jaakko Kangasharju
 * Copyright: GNU/GPL 2004
 */

package jip;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * A class representing a HIP address.  This class can be seen as a
 * specialization of {@link InetAddress} that only contains HIP
 * addresses.  This class also implements useful static methods for
 * handling HIP addresses.
 *
 * <p>Currently this class only contains static methods to resolve
 * hostnames to addresses.  In fact, until the move to the native HIP
 * API happens, objects of this class probably cannot be created at
 * all, since the networking in Java needs {@link InetAddress}
 * objects, which class cannot be extended outside the {@link
 * java.net} package.
 *
 * @author Jaakko Kangasharju
 */
public class HipAddress {

    static {
	System.loadLibrary("jip");
	nativeInit();
    }

    private short value;

    /*
     * At this point we have no use for HipAddress objects, so we
     * don't want anybody instantiating them.
     */
    private HipAddress (short value) {
	this.value = value;
    }

    private native static void nativeInit ();

    public native static HipAddress[] getAllByName (String host);

    public static HipAddress getByName (String host) {
	return getAllByName(host)[0];
    }

    public static HipAddress[] getAllByAddress (InetAddress addr) {
	return getAllByName(addr.getHostName());
    }

    public static HipAddress getByAddress (InetAddress addr) {
	return getAllByAddress(addr)[0];
    }

}
