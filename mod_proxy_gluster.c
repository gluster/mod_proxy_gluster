/*
 * Copyright 2014 Niels de Vos <ndevos@redhat.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Gluster routines for Apache proxy, based heavily on mod_proxy_ftp */

#define APR_WANT_BYTEFUNC
#include "mod_proxy.h"
#if APR_HAVE_TIME_H
#include <time.h>
#endif

#include <api/glfs.h>
#define GLFS_GLUSTERD_PORT 24007

#include <stddef.h>             /* For offsetof */


module AP_MODULE_DECLARE_DATA proxy_gluster_module;

/* from samba/source3/modules/vfs_gluster.c */
/* pre-opened glfs_t */

struct glfs_preopened
{
    char *volume;
    glfs_t *fs;
    int ref;
    struct glfs_preopened *next, *prev;
};

static apr_hash_t *glfs_preopened;
static apr_thread_mutex_t *glfs_preopened_lock;

static int
proxy_glfs_set_preopened(apr_pool_t * p, const char *volume, glfs_t * fs)
{
    struct glfs_preopened *entry = NULL;

    entry = malloc(sizeof(struct glfs_preopened));
    if (!entry) {
        errno = ENOMEM;
        return -1;
    }

    entry->volume = apr_pstrdup(p, volume);
    if (!entry->volume) {
        free(entry);
        errno = ENOMEM;
        return -1;
    }

    entry->fs = fs;
    entry->ref = 1;

    apr_hash_set(glfs_preopened, entry->volume, APR_HASH_KEY_STRING, entry);

    return 0;
}

static glfs_t *proxy_glfs_find_preopened(const char *volume)
{
    return (glfs_t *) apr_hash_get(glfs_preopened, volume,
                                   APR_HASH_KEY_STRING);
}

/* TODO
 * - glfs_clear_preopened() should be used to close the glfs_t
 * - unclear where to add a hook on-child-exit for glfs_clear_preopened() */
static void proxy_glfs_clear_preopened(glfs_t * fs)
{
    int remove = 0;
    char *volume = NULL;
    struct glfs_preopened *entry = NULL;
    apr_hash_index_t *hi;

    for (hi = apr_hash_first(NULL, glfs_preopened); hi;
         hi = apr_hash_next(hi)) {
        apr_hash_this(hi, (const void **) &volume, NULL, (void **) &entry);

        if (entry->fs == fs) {
            if (--entry->ref)
                return;

            remove = 1;
            break;
        }
    }

    if (remove) {
        apr_hash_set(glfs_preopened, volume, APR_HASH_KEY_STRING, NULL);
        glfs_fini(entry->fs);
        free(entry);
    }
}


/* one glfs_t per configuration / <Location> */
typedef struct
{
    glfs_t *fs;
    char *server;
    char *volume;
    char *logfile;
    int loglevel;
} proxy_glfs_dir_conf;


static void *create_proxy_glfs_dir_config(apr_pool_t * p, char *dummy)
{
    proxy_glfs_dir_conf *new =
        (proxy_glfs_dir_conf *) malloc(sizeof(proxy_glfs_dir_conf));

    new->fs = NULL;
    new->server = NULL;
    new->volume = NULL;
    /* TODO: log to /dev/stderr, but it doesn't work */
    new->logfile = "/dev/null";
    /* TODO: enable debug by default, its broken anyway */
    new->loglevel = LOG_DEBUG;

    return (void *) new;
}


static glfs_t *proxy_glfs_get_fs(apr_pool_t * p, request_rec * r,
                                 const proxy_glfs_dir_conf * dconf)
{
    glfs_t *fs = NULL;
    int err = 0;

    apr_thread_mutex_lock(glfs_preopened_lock);
    fs = proxy_glfs_find_preopened(dconf->volume);

    if (fs == NULL) {
        fs = glfs_new(dconf->volume);

        if (fs == NULL) {
            apr_thread_mutex_unlock(glfs_preopened_lock);
            return NULL;
            /* TODO
               return glfs_proxyerror(r, dconf,
               HTTP_SERVICE_UNAVAILABLE,
               "out of memory?");
             */
        }

        err = glfs_set_logging(fs, dconf->logfile, dconf->loglevel);
        if (err) {
            apr_thread_mutex_unlock(glfs_preopened_lock);
            return NULL;
            /* TODO
               return glfs_proxyerror(r, dconf,
               HTTP_SERVICE_UNAVAILABLE,
               "failed to 'set_logging'");
             */
        }

        if (glfs_set_volfile_server(fs, "tcp", dconf->server, 0)) {
            apr_thread_mutex_unlock(glfs_preopened_lock);
            return NULL;
            /* TODO
               return glfs_proxyerror(r, dconf,
               HTTP_SERVICE_UNAVAILABLE,
               "failed to 'set_volfile'");
             */
        }

        if (glfs_init(fs)) {
            apr_thread_mutex_unlock(glfs_preopened_lock);
            return NULL;
            /* TODO
               return glfs_proxyerror(r, dconf,
               HTTP_SERVICE_UNAVAILABLE,
               "failed to connect to Gluster volume");
             */
        }

        proxy_glfs_set_preopened(p, dconf->volume, fs);
    }
    apr_thread_mutex_unlock(glfs_preopened_lock);

    return fs;
}

/*
 * Decodes a '%' escaped string, and returns the number of characters
 */
static int decodeenc(char *x)
{
    int i, j, ch;

    if (x[0] == '\0')
        return 0;               /* special case for no characters */
    for (i = 0, j = 0; x[i] != '\0'; i++, j++) {
        /* decode it if not already done */
        ch = x[i];
        if (ch == '%' && apr_isxdigit(x[i + 1])
            && apr_isxdigit(x[i + 2])) {
            ch = ap_proxy_hex2c(&x[i + 1]);
            i += 2;
        }
        x[j] = ch;
    }
    x[j] = '\0';
    return j;
}

/*
 * Canonicalise URLs.
 */
static int proxy_glfs_canon(request_rec * r, char *url)
{
    if (strncasecmp(url, "gluster:", 8) != 0 || r->method_number != M_GET)
        return DECLINED;

    return OK;
}

/* this is a filter that turns a raw ASCII directory listing into pretty HTML */

/* ideally, mod_proxy should simply send the raw directory list up the filter
 * stack to mod_autoindex, which in theory should turn the raw ascii into
 * pretty html along with all the bells and whistles it provides...
 *
 * all in good time...! :)
 */

typedef struct
{
    char buffer[MAX_STRING_LEN];
    enum
    {
        HEADER, BODY, FOOTER
    } state;
} proxy_dir_ctx_t;

static
    apr_status_t proxy_send_dir_listing(request_rec * r,
                                        proxy_glfs_dir_conf * dconf,
                                        char *_dir)
{
    conn_rec *c = r->connection;
    apr_pool_t *p = r->pool;
    apr_bucket_brigade *out = apr_brigade_create(p, c->bucket_alloc);
    apr_status_t rv;
    struct dirent *pos = NULL;

    char *dir, *path, *reldir, *site, *str, *type;

    glfs_fd_t *fd = NULL;

    //const char *pwd = apr_table_get(r->notes, "Directory-PWD");

    proxy_dir_ctx_t *ctx = NULL;

    if (_dir == NULL || strlen(_dir) == 0)
        _dir = "/";

    ctx = apr_pcalloc(p, sizeof(*ctx));
    ctx->buffer[0] = 0;
    ctx->state = HEADER;

    if (HEADER == ctx->state) {
        /* basedir is either "", or "/%2f" for the "squid %2f hack" */
        const char *basedir = "";       /* By default, path is relative to the $HOME dir */
        char *wildcard = NULL;
        const char *escpath;

        /*
         * In the reverse proxy case we need to construct our site string
         * via ap_construct_url. For non anonymous sites apr_uri_unparse would
         * only supply us with 'username@' which leads to the construction of
         * an invalid base href later on. Losing the username part of the URL
         * is no problem in the reverse proxy case as the browser sents the
         * credentials anyway once entered.
         */
        if (r->proxyreq == PROXYREQ_REVERSE) {
            site = ap_construct_url(p, "", r);
        }
        else {
            /* Save "scheme://site" prefix without password */
            site = apr_uri_unparse(p, &r->parsed_uri,
                                   APR_URI_UNP_OMITPASSWORD |
                                   APR_URI_UNP_OMITPATHINFO);
        }

        /* ... and path without query args */
        path = apr_uri_unparse(p, &r->parsed_uri,
                               APR_URI_UNP_OMITSITEPART |
                               APR_URI_UNP_OMITQUERY);

        /* If path began with /%2f, change the basedir */
        if (strncasecmp(path, "/%2f", 4) == 0) {
            basedir = "/%2f";
        }

        /* Strip off a type qualifier. It is ignored for dir listings */
        if ((type = strstr(path, ";type=")) != NULL)
            *type++ = '\0';

        (void) decodeenc(path);

        /* Add a link to the root directory (if %2f hack was used) */
        str = (basedir[0] != '\0') ? "<a href=\"/%2f/\">%2f</a>/" : "";

        /* print "ftp://host/" */
        escpath = ap_escape_html(p, path);
        str = apr_psprintf(p, "<!--#include virtual=\"/includes/INDEXHEADER.html\"-->\n"); 

        str = apr_psprintf(p, "%s<h1 class=\"path\">Index of ", str);
        APR_BRIGADE_INSERT_TAIL(out,
                                apr_bucket_pool_create(str, strlen(str), p,
                                                       c->bucket_alloc));

        for (dir = path + 0; (dir = strchr(dir, '/')) != NULL;) {
            *dir = '\0';
            if ((reldir = strrchr(path + 1, '/')) == NULL) {
                reldir = path + 1;
            }
            else
                ++reldir;
            /* print "path/" component */
            str =
                apr_psprintf(p, "<a href=\"%s%s/\">%s</a>/",
                             basedir, ap_escape_uri(p, path),
                             ap_escape_html(p, reldir));
            *dir = '/';
            while (*dir == '/')
                ++dir;
            APR_BRIGADE_INSERT_TAIL(out,
                                    apr_bucket_pool_create(str, strlen(str),
                                                           p,
                                                           c->bucket_alloc));
        }
        if (wildcard != NULL) {
            wildcard = ap_escape_html(p, wildcard);
            APR_BRIGADE_INSERT_TAIL(out,
                                    apr_bucket_pool_create(wildcard,
                                                           strlen(wildcard),
                                                           p,
                                                           c->bucket_alloc));
        }

        /* TODO: insert <pre>README</pre> */
        str =
            apr_psprintf(p,
                         "</h1>\n<table width=\"100%%\">\n<thead>\n<tr>\n<th align=left>Name</th>\n"
                         "<th align=left>Last Modified</th>\n<th align=left>Size</th>\n</tr>\n"
                         "</thead>\n<tbody class=\"menuitem\">\n");
        APR_BRIGADE_INSERT_TAIL(out,
                                apr_bucket_pool_create(str, strlen(str), p,
                                                       c->bucket_alloc));

        rv = ap_pass_brigade(r->output_filters, out);
        if (rv != APR_SUCCESS)
            return rv;

        apr_brigade_cleanup(out);

        ctx->state = BODY;
    }

    fd = glfs_opendir(dconf->fs, _dir);
    if (fd == NULL) {
        str = apr_psprintf(p, "failed to opendir(\"%s\") with errno"
                           "%d", dir, errno);
        return ap_proxyerror(r, HTTP_BAD_REQUEST, str);
    }

    /* Print a leading Parent Directory option */

    str =
        apr_psprintf(p,
                     "<tr><td><img src=\"/icons/back.gif\" alt=\"[DIR]\"> <a href=\"%s/\">Parent directory</a></td></tr>\n",
                     //ap_escape_html(p, ctx->buffer), ap_escape_uri(p, ".."));
                     ap_escape_uri(p, ".."));

    APR_BRIGADE_INSERT_TAIL(out,
                            apr_bucket_pool_create(str, strlen(str), p,
                                                   c->bucket_alloc));

    rv = ap_pass_brigade(r->output_filters, out);
    if (rv != APR_SUCCESS)
        return rv;

    apr_brigade_cleanup(out);

    /* loop through each line of directory */
    while (BODY == ctx->state) {
        struct dirent *de = NULL;
        struct stat st;
        char *filename = NULL;
        int ret;
        char datestr[APR_RFC822_DATE_LEN];
        char humansize[10];

        /* TODO: maybe replace with malloc()/free()? */
        de = apr_pcalloc(p, offsetof(struct dirent, d_name) + NAME_MAX);

        ret = glfs_readdirplus_r(fd, &st, de, &pos);
        if (ret == 0 && pos == ((struct dirent *) NULL)) {
            ctx->state = FOOTER;
            break;
        }
        else if (ret != 0) {
            /* TODO: return sensible error */
            ctx->state = FOOTER;
            break;
        }

        filename = apr_pstrdup(p, de->d_name);

        if (S_ISLNK(st.st_mode)) {
            /* a symlink */
            char link_ptr[APR_PATH_MAX];
            char *full_path = NULL;
            full_path = apr_psprintf(p, "%s/%s", _dir, filename);
            ret = glfs_readlink(dconf->fs, full_path, link_ptr, APR_PATH_MAX);
            link_ptr[ret] = '\0';

            str =
                apr_psprintf(p,
                             "%s <img src=\"/icons/link.gif\" alt=\"[DIR]\"> <a href=\"%s\">%s -> %s</a>",
                             ap_escape_html(p, ctx->buffer), ap_escape_uri(p,
                                                                           filename),
                             ap_escape_html(p, filename), ap_escape_html(p,
                                                                         link_ptr));
            st.st_size = (ssize_t) - 1;
        }
        else if (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode)) {
            /* a directory/file */
            if (!strcmp(filename, ".")) {
                /* skip */
                continue;
            }
            else if (!strcmp(filename, "..")) {
                /* replace ".." by "Parent directory" */
                //str = apr_psprintf(p, "%s <a href=\"%s/\">"
                //                 "Parent directory</a>",
                //                 ap_escape_html(p,
                //                 ctx->buffer),
                //                 ap_escape_uri(p, filename));
                continue;
            }
            else if (S_ISDIR(st.st_mode)) {
                /* Append a slash to the HREF link for directories */
                if (strcmp(filename, ".~tmp~") == 0) {
                    continue;
                }
                else {
                    str =
                        apr_psprintf(p,
                                     "%s <img src=\"/icons/folder.gif\" alt=\"[DIR]\"> <a href=\"%s/\">%s</a>",
                                     ap_escape_html(p, ctx->buffer),
                                     ap_escape_uri(p, filename),
                                     ap_escape_html(p, filename));
                    st.st_size = (ssize_t) - 1;
                }
            }
            else {
                str =
                    apr_psprintf(p,
                                 "%s <img src=\"/icons/generic.gif\" alt=\"[   ]\"> <a href=\"%s\">%s</a>",
                                 ap_escape_html(p, ctx->buffer),
                                 ap_escape_uri(p, filename), ap_escape_html(p,
                                                                            filename));
            }
        }
        else {
            /* not a symlink, file or direcory; skip it */
            continue;
        }

        /* erase buffer for next time around */
        ctx->buffer[0] = 0;

        /* ISO8601 is preferrable to RFC822 time for indexes */
        strftime(datestr, sizeof(datestr), "%Y-%m-%d %H:%M",
                 localtime(&st.st_mtime));

        /* Use human friendly byte size display */
        apr_strfsize(st.st_size, humansize);

        if (st.st_size == -1) {
            str = apr_psprintf(p, "<tr><td>%s</td><td>%s</td>"
                               "<td>-</td></tr>\n", str, datestr);
        }
        else {
            str = apr_psprintf(p, "<tr><td>%s</td><td>%s</td>"
                               "<td>%s</td></tr>\n", str, datestr, humansize);
        }

        APR_BRIGADE_INSERT_TAIL(out,
                                apr_bucket_pool_create(str, strlen(str), p,
                                                       c->bucket_alloc));
        APR_BRIGADE_INSERT_TAIL(out,
                                apr_bucket_flush_create(c->bucket_alloc));

        rv = ap_pass_brigade(r->output_filters, out);
        if (rv != APR_SUCCESS)
            return rv;

        apr_brigade_cleanup(out);

    }

    glfs_closedir(fd);

    if (FOOTER == ctx->state) {
        const char *sig = "</table>\n"
            "<!--#include virtual=\"/includes/FOOTER.html\"-->\n";

        //str = apr_psprintf(p, "%s\n", ap_psignature(sig, r));
        str = apr_psprintf(p, "%s\n", sig);
        APR_BRIGADE_INSERT_TAIL(out,
                                apr_bucket_pool_create(str, strlen(str), p,
                                                       c->bucket_alloc));
        APR_BRIGADE_INSERT_TAIL(out,
                                apr_bucket_flush_create(c->bucket_alloc));
        APR_BRIGADE_INSERT_TAIL(out, apr_bucket_eos_create(c->bucket_alloc));

        rv = ap_pass_brigade(r->output_filters, out);
        if (rv != APR_SUCCESS)
            return rv;

        apr_brigade_destroy(out);
    }

    return OK;
}

static apr_status_t proxy_glfs_cleanup(proxy_glfs_dir_conf * conf)
{
    if (conf) {
        if (conf->fs)
            glfs_fini(conf->fs);

        /* TODO: not needed? segfaults...
           free(conf);
         */
    }

    return OK;
}

static int
glfs_proxyerror(request_rec * r, proxy_glfs_dir_conf * conf, int statuscode,
                const char *message)
{
    proxy_glfs_cleanup(conf);
    return ap_proxyerror(r, statuscode, message);
}

static int
proxy_glfs_handler(request_rec * r, proxy_worker * worker,
                   proxy_server_conf * conf, char *url, const char *proxyhost,
                   apr_port_t proxyport)
{
    apr_pool_t *p = r->pool;
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb = apr_brigade_create(p, c->bucket_alloc);
    apr_port_t connectport = 0;
    char *path = NULL;
    apr_uri_t uri;
    int len, rc;
    ssize_t size = 0;
    apr_time_t mtime = 0;
    int dirlisting = 0;
    struct stat st;
    proxy_glfs_dir_conf *dconf = ap_get_module_config(r->per_dir_config,
                                                      &proxy_gluster_module);

    /* is this for us? */
    if (proxyhost) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "declining URL "
                      "%s - proxyhost %s specified:", url, proxyhost);
        return DECLINED;        /* proxy connections are via HTTP */
    }
    if (strncasecmp(url, "gluster:", 8)) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "declining URL "
                      "%s - not gluster:", url);
        return DECLINED;        /* only interested in Gluster */
    }
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "serving URL %s", url);

    /* we only support GET and HEAD */
    if (r->method_number != M_GET)
        return HTTP_NOT_IMPLEMENTED;

    /* We break the URL into host, port, path-search */
    if (r->parsed_uri.hostname == NULL) {
        if (APR_SUCCESS != apr_uri_parse(p, url, &uri)) {
            char *err = NULL;
            err = apr_psprintf(p, "URI cannot be parsed: %s", url);
            return ap_proxyerror(r, HTTP_BAD_REQUEST, err);
        }
        dconf->server = uri.hostname;
        connectport = uri.port;
        len = (uri.path[0] == '/' ? 1 : 0);
        while (uri.path[len] != '/' && len < strlen(uri.path))
            len++;
        dconf->volume = apr_pstrndup(p, uri.path, len);
        path = apr_pstrdup(p, uri.path + len);
    }
    else {
        dconf->server = r->parsed_uri.hostname;
        connectport = r->parsed_uri.port;
        len = (r->parsed_uri.path[0] == '/' ? 1 : 0);
        while (r->parsed_uri.path[len] != '/'
               && len < strlen(r->parsed_uri.path))
            len++;
        dconf->volume = apr_pstrndup(p, r->parsed_uri.path, len);
        path = apr_pstrdup(p, r->parsed_uri.path + len);
    }
    if (path == NULL || strlen(path) == 0)
        path = apr_pstrdup(p, "/");

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "connecting %s to %s:%d",
                  url, dconf->server, connectport);

    if (dconf->fs == NULL) {
        dconf->fs = proxy_glfs_get_fs(p, r, dconf);

        if (dconf->fs == NULL)
            return glfs_proxyerror(r, dconf, HTTP_SERVICE_UNAVAILABLE,
                                   "Failed to connect to Gluster");
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "connected to the Gluster brick(s)");

    /* set request; "path" holds last path component */
    len = decodeenc(path);

    rc = glfs_stat(dconf->fs, path, &st);
    if (rc == -1) {
        /* try again, connection might have been terminated? */
        if (errno == ENOTCONN) {
            proxy_glfs_clear_preopened(dconf->fs);
            proxy_glfs_cleanup(dconf);

            dconf->fs = proxy_glfs_get_fs(p, r, dconf);
            if (dconf->fs)
                rc = glfs_stat(dconf->fs, path, &st);
        }

        if (rc == -1) {
            char *msg = NULL;
            msg = apr_psprintf(p, "File or directory not found "
                               "(path=%s, errno=%d)", path, errno);
            return glfs_proxyerror(r, dconf, HTTP_NOT_FOUND, msg);
        }
    }

    /* apr_time_t is in microseconds, time_t in seconds */
    mtime = st.st_mtime * 1000000;
    size = st.st_size;

    /* Check if a directory, and missing the trailing slash - redirect */
    if (S_ISDIR(st.st_mode) && strcmp(&path[len - 1], "/") != 0) {
        r->status = HTTP_MOVED_PERMANENTLY;
        r->status_line = "301 Moved Permanently";

        {
            char dates[APR_RFC822_DATE_LEN];
            apr_rfc822_date(dates, apr_time_now());
            apr_table_setn(r->headers_out, "Date", apr_pstrdup(p, dates));
            apr_table_setn(r->headers_out, "Server",
                           ap_get_server_description());
            apr_table_setn(r->headers_out, "Location",
                           apr_psprintf(p, "%s/", r->parsed_uri.path));
            ap_set_content_type(r,
                                apr_pstrcat(p, "text/html;charset=",
                                            "ISO-8859-1", NULL));
        }

        /* finish */
        /* TODO: we don't want to remove the glfs_t here... */
#if 0
        proxy_glfs_cleanup(conf);
#endif

        apr_brigade_destroy(bb);
        return OK;

    }



    /* TODO: check type of path */
    if (S_ISDIR(st.st_mode)) {
        dirlisting = 1;
    }
    /* TODO: invalid S_ISREG() check? */
#if 0
    else if (S_ISREG(st.st_mode)) {
        /* TODO: permission check? */
        mtime = st.st_mtime;
    }
    else {
        return glfs_proxyerror(r, dconf, HTTP_NOT_FOUND,
                               "not a file or directory");
    }
#endif

    if (path != NULL) {
        apr_table_set(r->notes, "Directory-PWD", path);
    }

    r->status = HTTP_OK;
    r->status_line = "200 OK";

    {
        char dates[APR_RFC822_DATE_LEN];
        apr_rfc822_date(dates, apr_time_now());
        apr_table_setn(r->headers_out, "Date", apr_pstrdup(p, dates));
        apr_table_setn(r->headers_out, "Server", ap_get_server_description());
    }

    /* set content-type */
    if (dirlisting) {
        ap_set_content_type(r, apr_pstrcat(p, "text/html;charset=",
                                           "ISO-8859-1", NULL));
    }
    else {
        apr_table_setn(r->headers_out, "Content-Length",
                       apr_psprintf(p, "%ld", size));
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "Content-Length set to %ld", size);
    }

    if (r->content_type) {
        apr_table_setn(r->headers_out, "Content-Type", r->content_type);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "Content-Type set to %s", r->content_type);
    }

    if (mtime != 0L) {
        char datestr[APR_RFC822_DATE_LEN];
        apr_rfc822_date(datestr, mtime);
        apr_table_set(r->headers_out, "Last-Modified", datestr);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "Last-Modified set to %s", datestr);
    }

    /* If an encoding has been set by mistake, delete it.
     * @@@ FIXME (e.g., for ftp://user@host/file*.tar.gz,
     * @@@        the encoding is currently set to x-gzip)
     */
    if (dirlisting && r->content_encoding != NULL)
        r->content_encoding = NULL;

    /* set content-encoding (not for dir listings, they are uncompressed) */
    if (r->content_encoding != NULL && r->content_encoding[0] != '\0') {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "Content-Encoding set to %s", r->content_encoding);
        apr_table_setn(r->headers_out, "Content-Encoding",
                       r->content_encoding);
    }

    /* send response */
    r->sent_bodyct = 1;

    /* send body */
    if (!r->header_only) {
        apr_bucket *e;
        int finish = FALSE;
        char buf[conf->io_buffer_size];
        glfs_fd_t *fd = NULL;
        ssize_t pos = 0;
        bb = apr_brigade_create(p, c->bucket_alloc);

        if (dirlisting)
            return proxy_send_dir_listing(r, dconf, path);

        fd = glfs_open(dconf->fs, path, O_RDONLY);

        if (fd == NULL) {
            /* TODO: check errno and return appropriate response codes */
            return glfs_proxyerror(r, dconf,
                                   HTTP_SERVICE_UNAVAILABLE,
                                   apr_psprintf(p,
                                                "failed to open file %s (errno=%d)",
                                                path, errno));
        }

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "start body send");

        /* read the body, pass it to the output filters */
        while (pos < size) {
            ssize_t len;
            len = glfs_pread(fd, &buf, conf->io_buffer_size, pos, 0);
            pos += len;

            if (ap_get_brigade(r->output_filters, bb, AP_MODE_READBYTES,
                               APR_BLOCK_READ, len) != APR_SUCCESS) {
                finish = TRUE;
            }
            else if (ap_fwrite(r->output_filters, bb, buf, len)
                     != APR_SUCCESS) {
                finish = TRUE;
                ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                              "ap_fwrite() failed");
                /* try send what we read */
            }
            else if (ap_pass_brigade(r->output_filters, bb)
                     != APR_SUCCESS || c->aborted) {
                /* Ack! Phbtt! Die! User aborted! */
                finish = TRUE;
            }

            /* if no EOS yet, then we must flush */
            if (FALSE == finish) {
                e = apr_bucket_flush_create(c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(bb, e);
            }

            /* make sure we always clean up after ourselves */
            apr_brigade_cleanup(bb);

            /* if we are done, leave */
            if (TRUE == finish) {
                break;
            }
        }

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "end body send");

        glfs_close(fd);
    }

    /* finish */
    /* TODO: we don't want to remove the glfs_t here... */
#if 0
    proxy_glfs_cleanup(conf);
#endif

    apr_brigade_destroy(bb);
    return OK;
}

static void ap_proxy_glfs_register_hook(apr_pool_t * p)
{
    /* init */
    /* TODO: create a (locked) list of glfs_t structures? */
    glfs_preopened = apr_hash_make(p);
    apr_thread_mutex_create(&glfs_preopened_lock, APR_THREAD_MUTEX_UNNESTED,
                            p);
    /* hooks */
    proxy_hook_scheme_handler(proxy_glfs_handler, NULL, NULL,
                              APR_HOOK_MIDDLE);
    proxy_hook_canon_handler(proxy_glfs_canon, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA proxy_gluster_module = {
    STANDARD20_MODULE_STUFF,
    create_proxy_glfs_dir_config,       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    NULL,                       /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    NULL,                       /* command apr_table_t */
    ap_proxy_glfs_register_hook /* register hooks */
};
