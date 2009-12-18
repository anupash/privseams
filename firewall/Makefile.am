AUTOMAKE_OPTIONS = foreign

CFLAGS = $(hipl_common_cflags)

if HIP_FIREWALL

sbin_PROGRAMS = hipfw

hipfw_SOURCES =	firewall.c \
				conntrack.c \
				rule_management.c \
				helpers.c \
				firewall_control.c \
				proxydb.c \
				conndb.c \
				dlist.c \
				hslist.c \
				user_ipsec_api.c \
				user_ipsec_esp.c \
				user_ipsec_sadb.c \
				user_ipsec_fw_msg.c \
				common_hipd_msg.c \
				esp_prot_api.c \
				esp_prot_fw_msg.c \
				esp_prot_conntrack.c \
				esp_prot_config.c \
				proxy.c \
				opptcp.c \
				firewalldb.c \
				lsi.c \
				sysopp.c \
				sava_api.c \
				cache.c \
				cache_port.c \
				datapkt.c
				
if HIP_MIDAUTH
hipfw_SOURCES += midauth.c \
				pisa.c \
				pisa_cert.c
endif

# libraries that are not found using AC_CHECK_LIB
hipfw_LDADD =	../libhipcore/.libs/libhipcore.a \
				../libhiptool/.libs/libhiptool.a
				
if HIP_LIBINET6
hipfw_LDADD +=	../libinet6/.libs/libinet6.a
endif

if HIP_PERFORMANCE
hipfw_LDADD +=	../performance/.libs/libperformance.a
endif

endif
