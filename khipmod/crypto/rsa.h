/* rsa.h
 *	Copyright (C) 1997,1998 by Werner Koch (dd9jn)
 *	Copyright (C) 2000, 2001, 2002 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */
#ifndef G10_RSA_H
#define G10_RSA_H

#ifdef __KERNEL__
#  include "kernel-interface.h"
#else
#  include <gcrypt.h>
#endif /* __KERNEL__ */

#include <net/hip.h>

int impl_rsa_sign(u8 *digest, u8 *private_key, u8 *signature,
		 int priv_klen);
int impl_rsa_verify(u8 *digest, u8 *public_key, u8 *signature,
		    int pub_klen);

#endif /*G10_RSA_H*/
