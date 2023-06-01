#ifndef KHTTPD_HTTP_SERVER_H
#define KHTTPD_HTTP_SERVER_H

#include <linux/kthread.h>
#include <net/sock.h>


#define MODULE_NAME "khttpd"

extern struct task_struct *my_kthread_run(int (*threadfn)(void *data),
                                          void *data,
                                          const char *namefmt,
                                          ...);

struct http_server_param {
    struct socket *listen_socket;
};

struct httpd_service {
    bool is_stopped;
    struct list_head worker_list;
};

struct khttpd {
    struct socket *sock;
    struct list_head list;
    struct work_struct khttpd_work;
};

extern int http_server_daemon(void *arg);

#endif
