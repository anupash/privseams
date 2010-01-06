AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = $(wildcard *.h)

noinst_LIBRARIES = libi3.a

# NOTE: this would overwrite AM_CFLAGS, so we need to append it
libi3_a_CFLAGS = `xml2-config --cflags` @AM_CFLAGS@

libi3_a_SOURCES = i3_addr.c \
                  i3_config.c \
                  i3_id.c \
                  i3_options.c \
                  i3_tcp_fns.c \
                  i3_utils.c \
                  i3_api.c \
                  i3_header.c \
                  i3_misc.c \
                  i3_stack.c \
                  i3_trigger.c \
                  i3_ping.c \
                  token_bucket.c
