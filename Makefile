LIBS=.libs/mod_proxy_gluster.so
PKGCONFIG=`pkg-config glusterfs-api --cflags-only-I --libs-only-l`

all: $(LIBS)

.libs/mod_proxy_gluster.so:
	apxs -c $(PKGCONFIG) mod_proxy_gluster.c

clean: 
	rm -f .libs/* *.o *.lo *.slo *.la

pretty:
	indent -i4 -npsl -di0 -br -nce -d0 -cli0 -npcs -nfc1 -nut mod_proxy_gluster.c && rm -v mod_proxy_gluster.c~

