AUTOMAKE_OPTIONS = foreign

XML_CFLAGS = `xml2-config --cflags`

EXTRA_DIST = $(wildcard *.h)

CFLAGS = $(hipl_common_cflags) $(XML_CFLAGS)

noinst_LIBRARIES = libi3.a

utils_SOURCES = ../utils/byteorder.c
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
                  token_bucket.c \
                  $(utils_SOURCES)
