
# mod_proxy_gluster
Modified mod_proxy_gluster supporting large files, ISO8601 times, and icons in much the same manner as the normal mod_autoindex from Apache. This module has been tested on both Apache 2.2 and 2.4. 

# SYNOPSIS

mod_proxy and related modules implement a proxy/gateway for Apache HTTP Server, supporting a number of popular protocols as well as several different load balancing algorithms.

This module adds support for accessing Gluster Volumes without the need to mount them with glusterfs-fuse or NFS. The purpose is to serve static contents. Files are returned without passing through any interpreters.  mod_proxy_gluster is not intended to be used for storing web-applications (written in languages like PHP).

# DOCUMENTATION

This source was cloned from https://forge.gluster.org/mod_proxy_gluster See the Gluster Forge for more documentation for more details on mod_proxy_gluster. mod_proxy and its configuration directives are explained
in the Apache HTTP Server documentation at http://httpd.apache.org/docs/2.4/mod/mod_proxy.html.

See the mod_proxy_gluster.conf.example file for configuration directives.

For allowing unpriviledged users (like a webserver) to access the Gluster
Volumes, some preparations on the Gluster Storage Servers need to be taken
care of:

1. Allow non-root users to connect to glusterd
  In /etc/glusterfs/glusterd.vol add this option:
  
    `option rpc-auth-allow-insecure on`

    Restart the glusterd service after making this change.

2. Allow non-root users to connect to the bricks in the volume, the example below uses the volume called bigfiles

    `gluster volume set bigfiles server.allow-insecure on`

    Note: Some versions of Gluster require the volume to be stopped and started after changing server.allow-insecure. Gluster 3.6 and newer should not need that.

# BUILDING
There are three ways to build this module:

1. Run make and copy the resulting .so from the .libs 

2. Manually run

    `apxs -c $(pkg-config glusterfs-api --cflags-only-I --libs-only-l) mod_proxy_gluster.c`
    
    Copy the resulting .so file from the .libs build directory to the Apache modules directory
    
# CONTACT

General Gluster questions should be directed to the Gluster Users mailing list <gluster-users@gluster.org>.

Niels de Vos <ndevos@redhat.com> is the main developer of mod_proxy_gluster. For most suggestions and discussions send an email to the Gluster Developers Discussion List <gluster-devel@gluster.org> and add Niels on CC.

David Jericho <davidj@diskpig.org> extended the source for a mirroring service.
