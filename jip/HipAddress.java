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
    }

    /*
     * At this point we have no use for HipAddress objects, so we
     * don't want anybody instantiating them.
     */
    private HipAddress () {
    }

    private native static byte[][] getAddresses (String host);

    /**
     * Returns all HIP addresses of a host based on its name.  The
     * returned addresses can be used in conjunction with the {@link
     * HipSocket} socket implementation.
     *
     * @param host the name of the host, either DNS name or literal
     * IPv6 address
     * @return all known HIP addresses of <code>host</code>
     */
    public static InetAddress[] getAllByName (String host) {
	byte[][] addrs = getAddresses(host);
	InetAddress[] result = new InetAddress[addrs.length];
	try {
	    for (int i = 0; i < addrs.length; i++) {
		result[i] = InetAddress.getByAddress(addrs[i]);
	    }
	} catch (UnknownHostException ex) {
	    /*
	     * This exception cannot happen, since we know that
	     * getAddresses only returns proper arrays.  But print
	     * stack trace for debugging anyway.
	     */
	    ex.printStackTrace();
	}
	return result;
    }

    /**
     * Returns the primary HIP address of a host based on its name.
     * The returned address can be used in conjunction with the {@link
     * HipSocket} socket implementation.
     *
     * @param host the name of the host, either DNS name or literal
     * IPv6 address
     * @return the primary HIP address of <code>host</code>
     */
    public static InetAddress getByName (String host) {
	return getAllByName(host)[0];
    }

}
