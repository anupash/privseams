#include "preinput.h"

/**
 * hip_handle_esp - handle incoming ESP packet
 * @spi: SPI from the incoming ESP packet
 * @hdr: IPv6 header of the packet
 *
 * If the packet's SPI belongs to a HIP connection, the IPv6 addresses
 * are replaced with the corresponding HITs before the packet is
 * delivered to ESP.
 */
void hip_handle_esp(uint32_t spi, struct ipv6hdr *hdr)
{
	hip_xfrm_state *xs;

	/* We are called only from bh.
	 * No locking will take place since the data
	 * that we are copying is very static
	 */
	_HIP_DEBUG("SPI=0x%x\n", spi);
	xs = hip_xfrm_find(spi);
	if (!xs) {
		HIP_INFO("HT BYSPILIST: NOT found, unknown SPI 0x%x\n",spi);
		return;
	}

	/* New in draft-10: If we are responder and in some proper state, then
	   as soon as we receive ESP packets for a valid SA, we should transition
	   to ESTABLISHED state.
	   Since we want to avoid excessive hooks, we will do it here, although the
	   SA check is done later... (and the SA might be invalid).
	*/
     /*	if (ha->state == HIP_STATE_R2_SENT) {
		ha->state = HIP_STATE_ESTABLISHED;
		HIP_DEBUG("Transition to ESTABLISHED state from R2_SENT\n");
          FIXME: tkoponen, miika said this could be removed.. note, xs->state is readonly in kernel!
          }*/

	ipv6_addr_copy(&hdr->daddr, &xs->hit_our);
	ipv6_addr_copy(&hdr->saddr, &xs->hit_peer);

     //	hip_put_ha(ha); FIXME: tkoponen, what is this doing here?
	return;
}

