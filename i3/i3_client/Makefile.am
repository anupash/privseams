AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(wildcard *.h)

CFLAGS= $(hipl_common_cflags)

noinst_LIBRARIES = libi3client.a
                    
libi3client_a_SOURCES = downhill_simplex.c \
                        coordinates.c i3_client_api.c \
                        i3_client_api_ctx.c \
                        i3_client_api_ext.c \
                        i3_client_callback.c \
                        i3_client_context.c \
                        i3_client_fd.c \
                        i3_client_id.c \
                        i3_client_pkt.c \
                        i3_client_timer.c \
                        i3_client_trigger.c \
                        i3server_list.c \
                        ping.c \
                        ping_thread.c \
                        http.c \
                        qsort.c 
