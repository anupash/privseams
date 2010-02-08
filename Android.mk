

BASE_PATH := $(call my-dir)

BASE_C_INCLUDES := $(addprefix $(BASE_PATH)/, . hipd firewall libhipandroid libhipcore libhipconf libinet6 libinet6/include_glibc23 libhiptool libdht i3 i3/i3_client performance)


###########################################################
# hipd
###########################################################


LOCAL_PATH:= $(BASE_PATH)/hipd

include $(CLEAR_VARS)

LOCAL_SRC_FILES :=  update.c \
                    update_legacy.c \
                    hipd.c \
                    keymat.c \
                    blind.c \
                    hiprelay.c \
                    registration.c \
                    user.c \
                    hadb.c \
                    hadb_legacy.c \
                    oppdb.c \
                    close.c \
                    configfilereader.c \
                    input.c \
                    output.c \
                    hidb.c \
                    cookie.c \
                    netdev.c \
                    bos.c \
                    nat.c \
                    icookie.c \
                    init.c \
                    maintenance.c \
                    accessor.c \
                    oppipdb.c \
                    dh.c \
                    tcptimeout.c \
                    cert.c \
                    user_ipsec_sadb_api.c \
                    user_ipsec_hipd_msg.c \
                    esp_prot_hipd_msg.c \
                    esp_prot_anchordb.c \
                    hipqueue.c \
                    esp_prot_light_update.c \
                    nsupdate.c \
                    hit_to_ip.c


LOCAL_CFLAGS := -include $(BASE_PATH)/libhipandroid/libhipandroid.h \
                -DICMP6_FILTER=1 \
                -DANDROID_CHANGES \
                -DCONFIG_HIP_LIBHIPTOOL \
                -DHIPL_DEFAULT_PREFIX=\"/system/\" \
                -DHIPL_SYSCONFDIR=\"/data/\" \
                -DHIPL_LOCKDIR=\"/data/\" \
                -DHAVE_OPENSSL_DSA_H=1 \
                -DHAVE_LIBSQLITE3=1 \
                -DHAVE_LIBXML2=1 \
                -DHIPL_HIPD \
                -DCONFIG_HIP_FIREWALL \
                -DCONFIG_HIP_RVS \
                -DCONFIG_HIP_HIPPROXY \
                -DCONFIG_HIP_OPPORTUNISTIC \
                -DCONFIG_SAVAH_IP_OPTION \
                -DCONFIG_HIP_DEBUG \
                -DHIP_LOGFMT_LONG \
                -g
# -DCONFIG_HIP_AGENT
# -DCONFIG_HIP_OPENDHT
# -DCONFIG_HIP_I3

LOCAL_C_INCLUDES := $(BASE_C_INCLUDES) \
                    external/openssl/include

LOCAL_SHARED_LIBRARIES := libcrypto

LOCAL_STATIC_LIBRARIES := libhipcore libhiptool libhipandroid libhipconf libinet6

LOCAL_MODULE:= hipd

LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_EXECUTABLE)


###########################################################
# hipconf
###########################################################


LOCAL_PATH:= $(BASE_PATH)/tools

include $(CLEAR_VARS)

LOCAL_SRC_FILES :=  hipconftool.c

LOCAL_CFLAGS := -include $(BASE_PATH)/libhipandroid/libhipandroid.h \
                -DANDROID_CHANGES \
                -g

LOCAL_C_INCLUDES := $(BASE_C_INCLUDES) \
                    external/openssl/include

LOCAL_SHARED_LIBRARIES := libcrypto

LOCAL_STATIC_LIBRARIES := libhipcore libhiptool libhipandroid libinet6 libhipconf

LOCAL_MODULE:= hipconf

LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_EXECUTABLE)


###########################################################
# hipfw
###########################################################


LOCAL_PATH:= $(BASE_PATH)/firewall

include $(CLEAR_VARS)

LOCAL_SRC_FILES :=  firewall.c \
                    conntrack.c \
                    rule_management.c \
                    helpers.c \
                    firewall_control.c \
                    esp_decrypt.c \
                    proxydb.c \
                    conndb.c \
                    datapkt.c \
                    dlist.c \
                    hslist.c \
                    user_ipsec_api.c \
                    user_ipsec_esp.c \
                    user_ipsec_sadb.c \
                    user_ipsec_fw_msg.c \
                    esp_prot_api.c \
                    esp_prot_fw_msg.c \
                    esp_prot_conntrack.c \
                    proxy.c \
                    opptcp.c \
                    firewalldb.c \
                    lsi.c \
                    sava_api.c \
                    cache.c \
                    cache_port.c \
                    esp_prot_config.c

LOCAL_CFLAGS := -include $(BASE_PATH)/libhipandroid/libhipandroid.h \
                -DANDROID_CHANGES \
                -DCONFIG_HIP_DEBUG \
                -DHIP_LOGFMT_LONG \
                -DHIPL_SYSCONFDIR=\"/data/\" \
                -DHIPL_LOCKDIR=\"/data/\" \
                -g

LOCAL_C_INCLUDES := $(BASE_C_INCLUDES) \
                    external/openssl/include \
                    external/iptables/include/libipq

LOCAL_SHARED_LIBRARIES := libcrypto

LOCAL_STATIC_LIBRARIES := libhipcore libhiptool libhipandroid libinet6

LOCAL_MODULE:= hipfw

LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_EXECUTABLE)


##########################################################
# libhipandroid
##########################################################


LOCAL_PATH:= $(BASE_PATH)/libhipandroid

include $(CLEAR_VARS)

LOCAL_SRC_FILES :=  libhipandroid.c \
                    regex.c \
                    libipq.c

LOCAL_CFLAGS := -include $(BASE_PATH)/libhipandroid/libhipandroid.h \
                -DANDROID_CHANGES \
                -g

LOCAL_C_INCLUDES := $(BASE_C_INCLUDES) \
                    external/iptables/include

LOCAL_SHARED_LIBRARIES :=

LOCAL_MODULE:= libhipandroid

LOCAL_MODULE_CLASS := STATIC_LIBRARIES

include $(BUILD_STATIC_LIBRARY)


# ###########################################################
# ## libhipcore
# ###########################################################


LOCAL_PATH:= $(BASE_PATH)/libhipcore

include $(CLEAR_VARS)

LOCAL_SRC_FILES :=  getendpointinfo.c \
                    debug.c \
                    builder.c \
                    misc.c \
                    message.c \
                    certtools.c \
                    linkedlist.c \
                    sqlitedbapi.c \
                    hip_statistics.c \
                    esp_prot_common.c \
                    hashchain_store.c \
                    hashchain.c \
                    hashtree.c \
                    hashtable.c \
                    utils.c

LOCAL_CFLAGS += -include $(BASE_PATH)/libhipandroid/libhipandroid.h \
                -DANDROID_CHANGES \
                -DICMP6_FILTER=1 \
                -DHIPL_DEFAULT_PREFIX=\"/system/\" \
                -DHIPL_SYSCONFDIR=\"/data/\" \
                -DHIPL_LOCKDIR=\"/data/\" \
                -DCONFIG_HIP_OPPORTUNISTIC \
                -DCONFIG_HIP_DEBUG \
                -DCONFIG_HIP_HIPPROXY \
                -DCONFIG_HIP_I3 \
                -DCONFIG_HIP_LIBHIPTOOL \
                -DCONFIG_HIP_RVS \
                -DHIP_TRANSPARENT_API \
                -g -O0 #TODO High optimization produces a crash at simulator, but not at the device?!

LOCAL_C_INCLUDES := $(BASE_C_INCLUDES) \
                    external/openssl/include

LOCAL_STATIC_LIBRARIES := libhiptool libhipandroid

LOCAL_MODULE:= libhipcore

LOCAL_MODULE_CLASS := STATIC_LIBRARIES

include $(BUILD_STATIC_LIBRARY)

##########################################################
# libinet6
##########################################################


LOCAL_PATH:= $(BASE_PATH)/libinet6

include $(CLEAR_VARS)

LOCAL_SRC_FILES :=  ifaddrs.c \
                    ifnames.c

LOCAL_CFLAGS := -include $(BASE_PATH)/libhipandroid/libhipandroid.h \
                -DANDROID_CHANGES \
                -g

LOCAL_C_INCLUDES := $(BASE_C_INCLUDES) \
                    external/openssl/include

LOCAL_SHARED_LIBRARIES :=

LOCAL_MODULE:= libinet6

LOCAL_MODULE_CLASS := STATIC_LIBRARIES

include $(BUILD_STATIC_LIBRARY)


# ###########################################################
# ## libhiptool
# ###########################################################


LOCAL_PATH:= $(BASE_PATH)/libhiptool

include $(CLEAR_VARS)

LOCAL_SRC_FILES :=  crypto.c \
                    pk.c \
                    nlink.c \
                    xfrmapi.c \
                    lutil.c

LOCAL_CFLAGS := -include $(BASE_PATH)/libhipandroid/libhipandroid.h \
                -DCONFIG_HIP_LIBHIPTOOL \
                -DHIPL_DEFAULT_PREFIX=\"/system/\" \
                -DANDROID_CHANGES \
                -g

LOCAL_C_INCLUDES := $(BASE_C_INCLUDES) \
                    external/openssl/include

LOCAL_STATIC_LIBRARIES := libhipcore

LOCAL_MODULE:= libhiptool

LOCAL_MODULE_CLASS := STATIC_LIBRARIES

include $(BUILD_STATIC_LIBRARY)


###########################################################
## libhipconf
###########################################################


LOCAL_PATH := $(BASE_PATH)/libhipconf

include $(CLEAR_VARS)

LOCAL_SRC_FILES :=  hipconf.c

LOCAL_CFLAGS := -include $(BASE_PATH)/libhipandroid/libhipandroid.h \
                -DANDROID_CHANGES \
                -DHIPL_DEFAULT_PREFIX=\"/system/\" \
                -DHIPL_SYSCONFDIR=\"/data/\" \
                -DHIPL_LOCKDIR=\"/data/\" \
                -g

LOCAL_C_INCLUDES := $(BASE_C_INCLUDES) \
                    external/openssl/include

LOCAL_MODULE:= libhipconf

LOCAL_MODULE_CLASS := STATIC_LIBRARIES

include $(BUILD_STATIC_LIBRARY)
