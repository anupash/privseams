lib_LTLIBRARIES += modules/signaling/hipd/libhipsignaling.la \
                   modules/signaling/lib/libhipsignaling_common.la \
                   modules/signaling/firewall/libhipsignaling_hipfw.la

modules_signaling_hipd_libhipsignaling_la_SOURCES = modules/signaling/hipd/signaling.c \
                                                    modules/signaling/hipd/signaling_hipd_msg.c \
                                                    modules/signaling/hipd/signaling_state.c \
                                                    modules/signaling/hipd/signaling_hipd_builder.c \
                                                    modules/signaling/hipd/signaling_hipd_user_msg.c \
                                                    modules/signaling/hipd/signaling_netstat_api.c

modules_signaling_lib_libhipsignaling_common_la_SOURCES = modules/signaling/lib/signaling_common_builder.c \
                                                          modules/signaling/lib/signaling_prot_common.c

modules_signaling_firewall_libhipsignaling_hipfw_la_SOURCES = modules/signaling/firewall/signaling_hipfw.c \
                                                              modules/signaling/firewall/signaling_cdb.c

hipd_hipd_LDADD += modules/signaling/hipd/libhipsignaling.la \
                   modules/signaling/lib/libhipsignaling_common.la \
                   -L/home/ziegeldorf/thesisrepository/code/x509ac -lx509ac -lssl

firewall_hipfw_LDADD += modules/signaling/firewall/libhipsignaling_hipfw.la \
                        modules/signaling/lib/libhipsignaling_common.la
