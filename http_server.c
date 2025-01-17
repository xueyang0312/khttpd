#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/err.h>
#include <linux/fs.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/workqueue.h>

#include "http_parser.h"
#include "http_server.h"

#define CRLF "\r\n"
#define CMWQ_MODE 0
#define PATH "/home/oslab/xueyang/linux2023/khttpd"

#define HTTP_RESPONSE_200_DUMMY                             \
    ""                                                      \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF   \
    "Content-Type: text/html" CRLF "Connection: Close" CRLF \
    "Transfer-Encoding: chunked" CRLF CRLF
#define HTTP_RESPONSE_200_KEEPALIVE_DUMMY                        \
    ""                                                           \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF        \
    "Content-Type: text/html" CRLF "Connection: Keep-Alive" CRLF \
    "Transfer-Encoding: chunked" CRLF CRLF
#define HTTP_RESPONSE_501                                              \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: Close" CRLF CRLF "501 Not Implemented" CRLF
#define HTTP_RESPONSE_501_KEEPALIVE                                    \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: KeepAlive" CRLF CRLF "501 Not Implemented" CRLF
/**
 * * If CRLF must be included in chunk data, the len of CRLF is 2.
 * * The len of chunk data is len of char array + 2 * the number of CRLF.
 */
#define HTTP_RESPONSE_DIRECTORY_LIST_BEGIN                \
    ""                                                    \
    "7B" CRLF "<html><head><style>" CRLF                  \
    "body{font-family: monospace; font-size: 15px;}" CRLF \
    "td {padding: 1.5px 6px;}" CRLF "</style></head><body><table>" CRLF
#define HTTP_RESPONSE_DIRECTORY_LIST_END \
    ""                                   \
    "16" CRLF "</table></body></html>" CRLF "0" CRLF CRLF

#define RECV_BUFFER_SIZE 4096

struct http_request {
    struct socket *socket;
    enum http_method method;
    char request_url[128];
    int complete;
    struct dir_context dir_context;
};

extern struct workqueue_struct *http_server_wq;
struct httpd_service daemon = {.is_stopped = false};

static int http_server_recv(struct socket *sock, char *buf, size_t size)
{
    struct kvec iov = {.iov_base = (void *) buf, .iov_len = size};
    struct msghdr msg = {.msg_name = 0,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    return kernel_recvmsg(sock, &msg, &iov, 1, size, msg.msg_flags);
}

static int http_server_send(struct socket *sock, const char *buf, size_t size)
{
    struct msghdr msg = {.msg_name = NULL,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    int done = 0;
    while (done < size) {
        struct kvec iov = {
            .iov_base = (void *) ((char *) buf + done),
            .iov_len = size - done,
        };
        int length = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (length < 0) {
            pr_err("write error: %d\n", length);
            break;
        }
        done += length;
    }
    return done;
}

static void http_server_send_header(struct socket *sock,
                                    int status,
                                    const char *status_msg,
                                    const char *content_type,
                                    int keep_alive,
                                    int content_length)
{
    char buf[256] = {0};
    snprintf(buf, sizeof(buf),
             "HTTP/1.1 %d %s" CRLF "Server: " KBUILD_MODNAME CRLF
             "Content-Type: %s" CRLF "Content-Length: %d" CRLF
             "Connection: %s" CRLF CRLF,
             status, status_msg, content_type, content_length,
             keep_alive ? "Keep-Alive" : "Close");
    http_server_send(sock, buf, strlen(buf));
}


static int http_server_trace_dir(struct dir_context *dir_context,
                                 const char *name,
                                 int namelen,
                                 loff_t offset,
                                 u64 ino,
                                 unsigned int d_type)
{
    if (strcmp(name, ".") && strcmp(name, "..")) {
        struct http_request *request =
            container_of(dir_context, struct http_request, dir_context);
        char buf[256] = {0};
        snprintf(buf, sizeof(buf),
                 "%x\r\n<tr><td><a href=\"%s\">%s</a></td></tr>\r\n",
                 33 + (namelen << 1), name, name);
        http_server_send(request->socket, buf, strlen(buf));
    }
    return 0;
}

static inline int read_file(struct file *fp, char *buf)
{
    return kernel_read(fp, buf, fp->f_inode->i_size, 0);
}

static void handle_directory(struct http_request *request, int keep_alive)
{
    char *response;
    char absolute_path[100];
    struct file *fp;

    request->dir_context.actor = http_server_trace_dir;

    if (request->method != HTTP_GET) {
        response = keep_alive ? HTTP_RESPONSE_501_KEEPALIVE : HTTP_RESPONSE_501;
        http_server_send(request->socket, response, strlen(response));
        return;
    }

    /* extern struct file *filp_open(const char *, int, umode_t); */
    memcpy(absolute_path, PATH, strlen(PATH));
    memcpy(absolute_path + strlen(PATH), request->request_url,
           strlen(request->request_url));
    absolute_path[strlen(PATH) + strlen(request->request_url)] = '\0';

    fp = filp_open(absolute_path, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        pr_err("open error: %s %ld\n", absolute_path, PTR_ERR(fp));
        return;
    } else {
        printk("open success: %s\n", absolute_path);
    }

    if (S_ISDIR(fp->f_inode->i_mode)) {
        response = keep_alive ? HTTP_RESPONSE_200_KEEPALIVE_DUMMY
                              : HTTP_RESPONSE_200_DUMMY;
        http_server_send(request->socket, response, strlen(response));

        response = HTTP_RESPONSE_DIRECTORY_LIST_BEGIN;
        http_server_send(request->socket, response, strlen(response));
        iterate_dir(fp, &request->dir_context);
        response = HTTP_RESPONSE_DIRECTORY_LIST_END;
        http_server_send(request->socket, response, strlen(response));
    } else {
        /* is a file */
        char *read_data = kmalloc(fp->f_inode->i_size, GFP_KERNEL);
        int ret = read_file(fp, read_data);
        if (ret < 0) {
            pr_err("read file error: %d\n", ret);
            return;
        }
        http_server_send_header(request->socket, 200, "OK", "text/plain",
                                keep_alive, ret);
        http_server_send(request->socket, read_data, ret);
        kfree(read_data);
    }
    filp_close(fp, NULL);
}

static int http_server_response(struct http_request *request, int keep_alive)
{
    handle_directory(request, keep_alive);
    return 0;
}

static int http_parser_callback_message_begin(http_parser *parser)
{
    struct http_request *request = parser->data;
    struct socket *socket = request->socket;
    memset(request, 0x00, sizeof(struct http_request));
    request->socket = socket;
    return 0;
}

static int http_parser_callback_request_url(http_parser *parser,
                                            const char *p,
                                            size_t len)
{
    struct http_request *request = parser->data;
    strncat(request->request_url, p, len);
    return 0;
}

static int http_parser_callback_header_field(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_header_value(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_headers_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    request->method = parser->method;
    return 0;
}

static int http_parser_callback_body(http_parser *parser,
                                     const char *p,
                                     size_t len)
{
    return 0;
}

static int http_parser_callback_message_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    http_server_response(request, http_should_keep_alive(parser));
    request->complete = 1;
    return 0;
}
#if CMWQ_MODE > 0

static void http_server_worker(struct work_struct *work)
{
    char *buf;
    struct khttpd *worker = container_of(work, struct khttpd, khttpd_work);
    struct socket *socket = worker->sock;
    struct http_request request;
    struct http_parser parser;
    struct http_parser_settings setting = {
        .on_message_begin = http_parser_callback_message_begin,
        .on_url = http_parser_callback_request_url,
        .on_header_field = http_parser_callback_header_field,
        .on_header_value = http_parser_callback_header_value,
        .on_headers_complete = http_parser_callback_headers_complete,
        .on_body = http_parser_callback_body,
        .on_message_complete = http_parser_callback_message_complete};

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    buf = kzalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("can't allocate memory!\n");
        return;
    }

    request.socket = socket;
    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &request;

    while (!daemon.is_stopped) {
        int ret;
        ret = http_server_recv(socket, buf, RECV_BUFFER_SIZE - 1);
        if (ret <= 0) {
            pr_err("read error: %d\n", ret);
            break;
        }
        http_parser_execute(&parser, &setting, buf, ret);
        if (request.complete && !http_should_keep_alive(&parser))
            break;
        memset(buf, 0, RECV_BUFFER_SIZE);
    }
    kernel_sock_shutdown(socket, SHUT_RDWR);
    sock_release(socket);
    kfree(buf);
    pr_info("http_server_worker exit\n");
}

static struct work_struct *create_work(struct socket *socket)
{
    struct khttpd *work = kmalloc(sizeof(struct khttpd), GFP_KERNEL);
    if (!work)
        return NULL;

    work->sock = socket;

    INIT_WORK(&work->khttpd_work, http_server_worker);

    list_add(&work->list, &daemon.worker_list);

    return &work->khttpd_work;
}

static void free_work(void)
{
    struct khttpd *safe, *next;
    list_for_each_entry_safe (safe, next, &daemon.worker_list, list) {
        kernel_sock_shutdown(safe->sock, SHUT_RDWR);
        flush_work(&safe->khttpd_work);
        sock_release(safe->sock);
        kfree(safe);
    }
}

#else

struct task_struct *my_kthread_run(int (*threadfn)(void *data),
                                   void *data,
                                   const char *namefmt,
                                   ...)
{
    // Call the original kthread_run function
    return kthread_run(threadfn, data, namefmt);
}

static int http_server_worker(void *arg)
{
    char *buf;
    struct http_parser parser;
    struct http_parser_settings setting = {
        .on_message_begin = http_parser_callback_message_begin,
        .on_url = http_parser_callback_request_url,
        .on_header_field = http_parser_callback_header_field,
        .on_header_value = http_parser_callback_header_value,
        .on_headers_complete = http_parser_callback_headers_complete,
        .on_body = http_parser_callback_body,
        .on_message_complete = http_parser_callback_message_complete};
    struct http_request request;
    struct socket *socket = (struct socket *) arg;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    buf = kzalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("can't allocate memory!\n");
        return -1;
    }

    request.socket = socket;
    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &request;
    while (!kthread_should_stop()) {
        /* kernel_recvmsg will return the numbers of bytes received */
        int ret = http_server_recv(socket, buf, RECV_BUFFER_SIZE - 1);
        if (ret <= 0) {
            if (ret)
                pr_err("recv error: %d\n", ret);
            break;
        }
        http_parser_execute(&parser, &setting, buf, ret);
        if (request.complete && !http_should_keep_alive(&parser))
            break;
        memset(buf, 0, RECV_BUFFER_SIZE);
    }
    kernel_sock_shutdown(socket, SHUT_RDWR);
    sock_release(socket);
    kfree(buf);
    return 0;
}
#endif

int http_server_daemon(void *arg)
{
    struct socket *client_socket;
    struct http_server_param *param = (struct http_server_param *) arg;
#if CMWQ_MODE > 0
    struct work_struct *work;
#else
    struct task_struct *worker;
#endif

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    INIT_LIST_HEAD(&daemon.worker_list);

    while (!kthread_should_stop()) {
        int err = kernel_accept(param->listen_socket, &client_socket, 0);
        if (err < 0) {
            if (signal_pending(current))
                break;
            pr_err("kernel_accept() error: %d\n", err);
            continue;
        }
#if CMWQ_MODE > 0

        if (unlikely(!(work = create_work(client_socket)))) {
            printk(KERN_ERR MODULE_NAME
                   ": create work error, connection closed\n");
            kernel_sock_shutdown(client_socket, SHUT_RDWR);
            sock_release(client_socket);
            continue;
        }

        /* start server worker */
        queue_work(http_server_wq, work);
#else
        worker =
            my_kthread_run(http_server_worker, client_socket, KBUILD_MODNAME);
        if (IS_ERR(worker)) {
            pr_err("can't create more worker process\n");
            continue;
        }
#endif
    }
#if CMWQ_MODE > 0
    printk(MODULE_NAME ": daemon shutdown in progress...\n");
    daemon.is_stopped = true;
    free_work();
#endif
    return 0;
}
