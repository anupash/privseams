/* dsa.h  -  DSA signature scheme
 *	Copyright (C) 1998, 2001, 2002 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
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
#ifndef G10_DSA_H
#define G10_DSA_H

#ifdef __KERNEL__
#  include "kernel-interface.h"
#else
#  include <gcrypt.h>
#endif /* __KERNEL__ */

#include <net/hip.h>

int impl_dsa_sign(u8 *digest, u8 *private_key, u8 *signature);
int impl_dsa_verify(u8 *digest, u8 *public_key, u8 *signature);

#endif /*G10_DSA_H*/
