lib_LTLIBRARIES += modules/signaling/hipd/libhipsignaling.la \
                   modules/signaling/lib/libhipsignaling_common.la

modules_signaling_hipd_libhipsignaling_la_SOURCES = modules/signaling/hipd/signaling.c \
                                                    modules/signaling/hipd/signaling_hipd_msg.c \
                                                    modules/signaling/hipd/signaling_state.c \
                                                    modules/signaling/hipd/signaling_hipd_builder.c \
                                                    modules/signaling/hipd/signaling_hipd_user_msg.c \
                                                    modules/signaling/hipd/signaling_netstat_api.c

modules_signaling_lib_libhipsignaling_common_la_SOURCES = modules/signaling/lib/signaling_common_builder.c

hipd_hipd_LDADD += modules/signaling/hipd/libhipsignaling.la \
                   modules/signaling/lib/libhipsignaling_common.la

firewall_hipfw_LDADD += modules/signaling/lib/libhipsignaling_common.la
