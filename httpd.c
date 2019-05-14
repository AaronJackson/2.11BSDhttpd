/* 2.11BSD httpd */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/stat.h>

#include <netdb.h>
#include <stdio.h>
#include <strings.h>

int main(argc, argv)
int argc;
char *argv[];
{
     char line[1024];
     int fd;
     struct stat st;
     char path[200];
     char *ext;
     int c;

     char req_verb[5];

     strncpy(path, "/var/www/", 200);
     while (fgets(line, sizeof(line), stdin) != NULL) {
       /* Detect the double line break to end req header */
       if (strlen(line) < 5) break;

       /* Get the path from the GET or POST request */
       if (strstr(line, "GET ") == line ||
	   strstr(line, "POST ") == line)
	 sscanf(line, "%s %s", req_verb, &path[strlen(path)]);
     }

     /* Check for parent directories in path */
     if (strstr(path, "..") != NULL)
       exit(1);

     /* Check that we are not going to dump an inode */
     if (path[strlen(path)-1] == '/')
       strcat(path, "/index.html");

     /* Request information about the file, such as the size... */
     stat(path, &st);

     /* Open file, 404 if not found. */
     fd = fopen(path, "r");
     if (fd == NULL) {
	  printf("HTTP/1.1 404 Not Found\r\n");
	  printf("Content-Type: text/plain\r\n\r\n");
	  printf("File not found.\r\n");
	  exit(1);
     }

     printf("HTTP/1.1 200 OK\r\n");

     /* Extract file type and output content-type header */
     ext = rindex(path, '.');
     if (!ext) ext = rindex(path, NULL);
     if (!strcmp(ext, ".html"))
	  printf("Content-Type: text/html\r\n");
     else if (!strcmp(ext, ".jpg"))
	  printf("Content-Type: image/jpeg\r\n");
     else
	  printf("Content-Type: text/plain\r\n");
     printf("Content-Length: %ld\r\n", st.st_size);

     printf("\r\n");

     while (feof(fd) == 0 && (c = fgetc(fd)) != -1)
       fputc(c, stdout);

     fclose(fd);
     return 0;
}
