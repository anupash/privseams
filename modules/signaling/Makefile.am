lib_LTLIBRARIES += modules/signaling/hipd/libhipsignaling.la \
                   modules/signaling/lib/libhipsignaling_common.la

modules_signaling_hipd_libhipsignaling_la_SOURCES = modules/signaling/hipd/signaling.c \
                                                    modules/signaling/hipd/signaling_builder.c \
                                                    modules/signaling/hipd/signaling_prot_hipd_msg.c

modules_signaling_lib_libhipsignaling_common_la_SOURCES = modules/signaling/lib/signaling_prot_common.c


hipd_hipd_LDADD += modules/signaling/hipd/libhipsignaling.la \
                   modules/signaling/lib/libhipsignaling_common.la
