#ifndef HIP_HIPD_UPDATE_LEGACY_H
#define HIP_HIPD_UPDATE_LEGACY_H

/**
 * Builds udp and raw locator items into locator list to msg
 * this is the extension of hip_build_locators in output.c
 * type2 locators are collected also
 *
 * @param msg          a pointer to hip_common to append the LOCATORS
 * @return             len of LOCATOR2 on success, or negative error value on error
 */
int hip_build_locators_old(struct hip_common *msg, uint32_t spi);

#endif /* HIP_HIPD_UPDATE_LEGACY_H */
