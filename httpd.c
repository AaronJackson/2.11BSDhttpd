/* 2.11BSD httpd */
#include <sys/types.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <sys/time.h>

#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CGI_BIN
#define CGI_FORWARD_REQUEST_PAYLOAD
/* #define DETAILED_LOGGING */
#define BUF_SIZE 256
#define PATH_LEN 512
#define WWW_ROOT "/home/www/"
#define LOGFILE "/usr/adm/httpd.log"

#define HTTP_200 "HTTP/1.1 200 OK"
#define HTTP_403 "HTTP/1.1 403 Forbidden"
#define HTTP_404 "HTTP/1.1 404 Not Found"
#define HTTP_500 "HTTP/1.1 500 Internal Server Error"

FILE *htlog;

#ifdef CGI_FORWARD_REQUEST_PAYLOAD

/* These values are conservative */
#define MAX_HEADER_BYTES_TO_FORWARD 5000
#define MAX_HEADER_ITEM_BYTES 500
#define MAX_HEADER_ITEM_COUNT 30
#define MAX_CONTENT_LENGTH_TO_FORWARD 10000

/* Linked list structure used to pass 
    request data to the CGI program */
struct linked_list {
    char *data;
    struct linked_list *next;
} *request_content = NULL;

/* Functions for managing the linked list */
int add_node();
char **get_parameters();

#endif /* CGI_FORWARD_REQUEST_PAYLOAD */

/* Get path information and handle errors */
void chk_path(path, st)
char *path;
struct stat *st;
{
    /* stat the path. If there's an error, log it and terminate. */
    if (stat(path, st) != 0) {
        if (errno & (ENOENT | ENOTDIR | EINVAL | ENAMETOOLONG)) {
            fprintf(htlog, "404 %s (%s)\n", strerror(errno), path);
            printf("%s\r\n", HTTP_403);
        } else if (errno & EACCES) {
            fprintf(htlog, "403 %s (%s)\n", strerror(errno), path);
            printf("%s\r\n", HTTP_403);
        } else {
            fprintf(htlog, "500 %s (%s)\n", strerror(errno), path);
            printf("%s\r\n", HTTP_500);
        }

        fclose(htlog);
        exit(1);
    }
}

int main(argc, argv)
int argc;
char *argv[];
{
    char path[PATH_LEN];
    struct stat st;
    struct itimerval timeout;

#ifdef CGI_FORWARD_REQUEST_PAYLOAD
    int is_content = 0;
    int content_length = -1;
    int content_bytes_read = 0;
    int request_header_bytes_used = 0;
    int request_header_item_count = 0;            
#endif

    /* Open log file, quit with HTTP 500 if there's an error */
    htlog = fopen(LOGFILE, "a");
    if (!htlog) {
        printf("%s\r\n", HTTP_500);
        exit(1);
    }

    /* Log requesting host address */
    {
        struct sockaddr_in sin;
        int sval;
        struct hostent *hp;
        char *host;

        sval = sizeof(sin);
        if (getpeername(0, (struct sockaddr *)&sin, &sval) == 0) {
            /* This is a connected socket, so get the address */
            if (hp = gethostbyaddr((char *)&sin.sin_addr.s_addr,
                        sizeof(sin.sin_addr.s_addr), AF_INET))
                host = hp->h_name;
            else
                host = inet_ntoa(sin.sin_addr);
        } else {
            /* Not a socket or address otherwise unavailable */
            host = strerror(errno);
        }

        fprintf(htlog, "%s ", host);
    }

    /* Log request time */
    {
        long secs;
        char *logtime;

        time(&secs);
        logtime = ctime(&secs);
        /* Strip trailing newline from ctime string */
        logtime[strcspn(logtime, "\r\n")] = '\0';
        fprintf(htlog, "[%s] ", logtime);
    }

    /* Path starts with WWW_ROOT */
    strncpy(path, WWW_ROOT, sizeof(path));

    /* Set a timeout to terminate the process if the client is holding the
     * socket open and not completing the http request */
    timerclear(&timeout.it_interval);
    timerclear(&timeout.it_value);
    timeout.it_value.tv_sec = 60;
    /* Default action for SIGALRM is to terminate the process, so no need
     * to set up a signal handler */
    setitimer(ITIMER_REAL, &timeout, 0);

    /* Fill in path with GET/POST request

       Optionally, pass parameters as arguments to CGI program. */
    {
        char line[PATH_LEN];
        char *lineptr;
                
        while (fgets(line, sizeof(line), stdin)) {

            /* Remove trailing newline left by fgets() */
            line[strcspn(line, "\r\n")] = '\0';

#ifdef CGI_FORWARD_REQUEST_PAYLOAD
            if (request_header_item_count < MAX_HEADER_ITEM_COUNT && 
                    request_header_bytes_used < MAX_HEADER_BYTES_TO_FORWARD) {
                int node_bytes = add_node(line, 0, 0);
                if (node_bytes > 0) {
                   request_header_bytes_used += node_bytes;
                   ++request_header_item_count;
                }
#ifdef DETAILED_LOGGING
            } else if (request_header_item_count >= MAX_HEADER_ITEM_COUNT) {
                fprintf(htlog, "Reached limit for number of payload items to forward\n");
            } else {
                fprintf(htlog, "Reached limit for number of bytes of payload to forward\n");
#endif
            }

            /* Detect the double line break to end req header and start content */
            if (strlen(line) == 0) {
#ifdef DETAILED_LOGGING
                fprintf(htlog, "Reached content, length %d\n", content_length);
#endif
                /* If Content-Length found, signal loading of content */
                if (content_length > 0) {
                    is_content = 1;
                }
                break;
            }
#else
           /* Detect the double line break to end req header */
            if (strlen(line) == 0)
                break;
#endif
            /* Get the path from the GET or POST request */
            if (strstr(line, "GET ") == line ||
                strstr(line, "POST ") == line) {

                fprintf(htlog, "\"%s\" ", line);

                /* Append rest of request to path */
                /* Skip request method */
                strtok(line, " ");
                /* Next token is path */
                lineptr = strtok(NULL, " ");
                if (lineptr) {
                    if (*lineptr == '/') {
                        ++lineptr;
                    }    
                    strncat(path, lineptr, sizeof(path)-strlen(path)-1);
                }
            }

#ifdef CGI_FORWARD_REQUEST_PAYLOAD
            /* Found the Content-Length. If within allowed range, store it */
            if (strstr(line, "Content-Length: ") == line) {
                int temp_length = atoi(line + strlen("Content-Length: "));
                if (temp_length > 0 || temp_length <= MAX_CONTENT_LENGTH_TO_FORWARD) {
                    content_length = temp_length;
#ifdef DETAILED_LOGGING
                    fprintf(htlog, "Content-Length: %d\n", content_length);
#endif
                }
            }
#endif
        }
    }

#ifdef CGI_FORWARD_REQUEST_PAYLOAD
    /* Get the content and place it in the request content linked list */
    if (is_content) {
        add_request_content_to_payload(content_length);
#ifdef DETAILED_LOGGING
    } else {
        fprintf(htlog, "No Content-Length in header, skip loading content\n");
#endif
    }
#endif 

    /* Cancel the timeout now that we have the http request */
    timerclear(&timeout.it_interval);
    timerclear(&timeout.it_value);
    setitimer(ITIMER_REAL, &timeout, 0);

    /* Check for parent directories in path */
    if (strstr(path, "/..")) {
        printf("%s\r\n", HTTP_403);
        fprintf(htlog, "403 Request contains \"..\"\n");
        fclose(htlog);
        exit(1);
    }
    
    /* stat the path and handle errors */
    chk_path(path, &st);

    /* If a directory is requested, default page is index.html */
    if (st.st_mode & S_IFDIR) {
        strncat(path, "index.html", sizeof(path)-strlen(path)-1);
        /* stat and handle errors again */
        chk_path(path, &st);
    }

    /* Only serve regular files */
    if (!(st.st_mode & S_IFREG)) {
        printf("%s\r\n", HTTP_403);
        fprintf(htlog, "403 Not a regular file\n");
        fclose(htlog);
        exit(1);
    }

#ifdef CGI_BIN
    /* Check if a CGI program has been requested */
    if (strstr(path, "/cgi-bin/")) {

        int pid;
        union wait status;
        
        /* CGI program must be executable and not setuid/setgid */
        if (!(st.st_mode & S_IEXEC) ||
                (st.st_mode & (S_ISUID | S_ISGID))) {
            printf("%s\r\n", HTTP_403);
            fprintf(htlog,
                    "403 File not executable and/or is setuid/setgid\n");
            fclose(htlog);
            exit(1);
        }
        
        /* Execute CGI program */
        if (!(pid = vfork())) {
            /* Child process */
#ifdef CGI_FORWARD_REQUEST_PAYLOAD
            /* Place program name in first argument */
            add_node(path, 1, 0);
            execve(path, get_parameters(), NULL);
#else
            execve(path, NULL, NULL);
#endif
            fprintf(htlog, "500 %s\n", strerror(errno));
            printf("%s\r\n", HTTP_500);
            _exit(1);

        } else {
            /* Parent process, wait for child to exit */
            wait(&status);

            if (WIFEXITED(status))
                fprintf(htlog, "Exited with status %d\n",
                    status.w_retcode);
/*                    (int)(WEXITSTATUS(status))); */
                    else if (WIFSIGNALED(status))
                fprintf(htlog, "Terminated with signal %d\n",
                    status.w_termsig);
/*                    (int)(WTERMSIG(status))); */
                }

    } else
#endif /* CGI_BIN */

    /* Serve the file */
    {
        FILE *fd;
        char *ext;

        char buf[BUF_SIZE];
        int pos;

        /* Open file */
        fd = fopen(path, "r");
        if (!fd) {
            /* Earlier stat should have caught any errors, so we shouldn't
             * get here unless the file changed after the call */
            fprintf(htlog, "500 %s\n", strerror(errno));
            printf("%s\r\n", HTTP_500);
            fclose(htlog);
            exit(1);
        }

        printf("%s\r\n", HTTP_200);
        fprintf(htlog, "200 %ld\n", st.st_size);

        /* Extract file type and output content-type header */
        ext = rindex(path, '.');
        if (!ext)
            ext = "";

        if (!strcmp(ext, ".html"))
            printf("Content-Type: text/html\r\n");
        else if (!strcmp(ext, ".jpg"))
            printf("Content-Type: image/jpeg\r\n");
        else if (!strcmp(ext, ".png"))
            printf("Content-Type: image/png\r\n");
        else if (!strcmp(ext, ".ico"))
            printf("Content-Type: image/x-icon\r\n");
        else
            printf("Content-Type: text/plain\r\n");

        printf("Content-Length: %ld\r\n\r\n", st.st_size);
        
        while (!feof(fd) &&
                (pos = fread(buf, sizeof(*buf), sizeof(buf), fd)) > 0)
            fwrite(buf, sizeof(*buf), pos, stdout);
        
        fclose(fd);
    }

    fclose(htlog);
    return 0;
}

#ifdef CGI_FORWARD_REQUEST_PAYLOAD

/* Add a node containing the param value to the linked list. 
    The value is copied into allocated memory before being added. 
    If at_front is non-zero (true), value inserted at front of the list. */
int add_node(param, at_front, ignore_size_limit)
char *param; 
int at_front;
int ignore_size_limit;
{
    char *param_storage = NULL;
    struct linked_list *node = NULL;
    int bytes_to_allocate;
    int bytes_allocated = 0;

    if (param == NULL) {
#ifdef DETAILED_LOGGING
        fprintf(htlog, "NULL request parameter, skip storing");
#endif
        return;
    }

    if (!ignore_size_limit && strlen(param) > MAX_HEADER_ITEM_BYTES) { 
#ifdef DETAILED_LOGGING
        fprintf(htlog, "Request parameter being ignored, too long (%d bytes): %s\n", strlen(param), param);
#endif
        return 0;
    }

    /* Allocate memory for parameter value */
    bytes_to_allocate = (strlen(param) + 1) * sizeof(char);
    errno = 0;
    param_storage = (char *) malloc(bytes_to_allocate);
    if (errno) {
#ifdef DETAILED_LOGGING
        fprintf(htlog, "Allocation error trying to store request parameter (%s): %s\n", strerror(errno), param);
#endif
        return 0;
    } else if (param_storage == NULL) {
#ifdef DETAILED_LOGGING
        fprintf(htlog, "Unable to store request parameter (no memory allocated): %s\n", param);
#endif
        return 0;
    }
    bytes_allocated += bytes_to_allocate;
#ifdef DETAILED_LOGGING
    fprintf(htlog, "Storing request param: %s\n", param);
#endif
    /* Allocate memory for node */
    bytes_to_allocate = sizeof(struct linked_list);
    errno = 0;
    node = (struct linked_list *) malloc(bytes_to_allocate);
    if (errno) {
#ifdef DETAILED_LOGGING
        fprintf(htlog, "Allocation error trying to create node for request parameter (%s): %s\n", strerror(errno), param);
#endif
        free(param_storage);
        return 0;
    } else if (param_storage == NULL) {
#ifdef DETAILED_LOGGING
        fprintf(htlog, "Unable to create node for request parameter (no memory allocated): %s\n", param);
#endif
        free(param_storage);
        return 0;
    }
    bytes_allocated += bytes_to_allocate;
    
    /* Populate the node */
    strcpy(param_storage, param);
    node->data = param_storage;
    node->next = NULL;

    /* Add the node to the linked list of parameters */
    if (request_content == NULL) {
        request_content = node;
    } else if (at_front) {
        /* insert new node at the front of the list */
        node->next = request_content;
        request_content = node;
    } else {
        /* insert new node at the end of the list */
        struct linked_list *next = request_content;
        while (next->next != NULL) {
            next = next->next;
        }
        next->next = node;
    }

#ifdef DETAILED_LOGGING
    fprintf(htlog, "Param added to linked list\n");
#endif

    return bytes_allocated;
}

void add_request_content_to_payload(content_length) 
int content_length;
{
    char *content;
    int bytes_read;

    errno = 0;
    content = (char *) malloc((content_length + 1) * sizeof(char));
    if (errno) {
#ifdef DETAILED_LOGGING
        fprintf(htlog, "Allocation error trying to store request content: length=%d\n", content_length);
#endif
        return;
    } else if (content == NULL) {
#ifdef DETAILED_LOGGING
        fprintf(htlog, "Unable to store request content (no memory allocated): length=%d\n", content_length);
#endif
        return;
    }
#ifdef DETAILED_LOGGING
    fprintf(htlog, "Reading content, up to %d bytes\n", content_length);
#endif

    bytes_read = fread(content, sizeof(char), content_length, stdin);
    *(content + bytes_read) = '\0';

#ifdef DETAILED_LOGGING
    fprintf(htlog, "Read %d bytes of content\n", bytes_read);
#endif

    add_node(content, 0, 1);
}

/* Get a vector of the parameter values to pass to the CGI program via execve(). */
char **get_parameters() {
    int num_parameters = 0;
    struct linked_list *next;
    char **parameters;

    if (!request_content) {
        return NULL;
    }

    for (next = request_content;next;next = next->next) {
        ++num_parameters;
    }

    /* Account for the null pointer for the end of the vector */
    ++num_parameters;

    /* Allocate the vector to hold the parameters */
    errno = 0;
    parameters = (char **) malloc(num_parameters * sizeof(char *));
    if (errno) {
#ifdef DETAILED_LOGGING
        fprintf(htlog, "Allocation error trying to create vector for %d request items (%s)\n", num_parameters, strerror(errno));
#endif
        return NULL;
    } else if (parameters == NULL) {
#ifdef DETAILED_LOGGING
        fprintf(htlog, "Unable to allocate vector for %d request items (no memory allocated)\n", num_parameters);
#endif
        return NULL;
    }

    num_parameters = 0;
    for (next = request_content;next;next = next->next) {
        *(parameters + num_parameters++) = next->data;
    }

    /* Add the null pointer at the end */
    *(parameters + num_parameters) = NULL;

    return parameters;
}

#endif /* CGI_FORWARD_REQUEST_PAYLOAD */
