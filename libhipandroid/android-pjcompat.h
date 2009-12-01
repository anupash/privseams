#ifndef ANDROID_PJCOMPAT_H
#define ANDROID_PJCOMPAT_H

#ifdef ANDROID_CHANGES
#ifndef s6_addr
#  define s6_addr                 in6_u.u6_addr8
#  define s6_addr16               in6_u.u6_addr16
#  define s6_addr32               in6_u.u6_addr32
#endif /* s6_addr */
#endif

#endif /* ANDROID_PJCOMPAT_H */
