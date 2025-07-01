/* myserver.c */

#include "myserver.h"
#include "database.h"


static volatile int keep_running = 1;

int active_connections = 0;

char *error;

static char stored_name[256] = "John Doe";
static int stored_age = 30;

void sigint_handler(int sig) {
	(void)sig;
	keep_running = 0;
}

int server_init(const char *bind_addr, int port_number) {
	int serv_fd;
	struct sockaddr_in addr;
	
	serv_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (serv_fd < 0) {
		error = "socket() failure";
		return 0;	
	}
	
	int opt = 1;
	if (setsockopt(serv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		fprintf(stderr, "setsockopt(SO_REUSEADDR) failure: %s\n", strerror(errno));
		close(serv_fd);
		error = "setsockopt() failure";
		return 0;
	}
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(bind_addr);
	if (addr.sin_addr.s_addr == INADDR_NONE) {
		error = "Invalid bind address";
		close(serv_fd);
		return 0;
	}
	addr.sin_port = htons(port_number);
	if ((bind(serv_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)) {
		error = "bind() failure";
		close(serv_fd);
		return 0;
	}
	if ((listen(serv_fd, 5)) < 0) {
		error = "listen() failure";
		close(serv_fd);
		return 0;
	}
	return serv_fd;
}


int cli_accept(int serv_fd) {	
	if (active_connections >= MAX_CONNECTIONS) {
		error = "Too many connections";
		return 0;
	}

	int cli_fd;
	struct sockaddr_in cli_addr;
	
	memset(&cli_addr, 0, sizeof(cli_addr));
	socklen_t addrlen = sizeof(cli_addr);
	
	cli_fd = accept(serv_fd, (struct sockaddr *)&cli_addr, &addrlen);
	if (cli_fd < 0) {	
		error = "cli_accept() failure";
		return 0;
	}
	active_connections++;	
	return cli_fd;
}

int http_headers(int cli_fd, int code) {
	char buf[512];
	ssize_t bytes;
	memset(buf, 0, sizeof(buf));

	snprintf(buf, 511,
			"HTTP/1.0 %d %s\r\n"
			"Server: myserver.c\r\n"
			"Cache-Control: no-store, no-cache, max-age=0, private\r\n"
			"Content-Language: en\r\n"
			"Expires: -1\r\n"
			"X-Frame-Options: SAMEORIGIN\r\n",
			code, code == 200 ? "OK" : code == 404 ? "Not Found" : code == 400 ? "Bad Request" : "Internal Server Error");
	bytes = write(cli_fd, buf, strlen(buf));
	if (bytes == -1) {
		error = "http_headers() write() failure";
		return 0;
	}
	return 1;
}

int http_response(int cli_fd, char *content_type, char *data) {
	char buf[2048];
	ssize_t bytes;
	memset(buf, 0, sizeof(buf));
	int n = strlen(data);

	snprintf(buf, sizeof(buf),
			"HTTP/1.0 200 OK\r\n"
			"Content-Type: %s\r\n"
			"Content-Length: %d\r\n\r\n"
			"%s",
			content_type, n, data);
	bytes = write(cli_fd, buf, strlen(buf));
	if (bytes == -1) {
		error = "http_response() write() failure";
		return 0;
	}
	return 1;
}

File *read_file(char *file_name) {
	File *f = malloc(sizeof(File));
	if (!f) {
		error = "read_file() malloc failure";
		return 0;
	}
	memset(f, 0, sizeof(File));
	strncpy(f->file_name, file_name, sizeof(f->file_name) - 1);

	f->fd = open(file_name, O_RDONLY);

	if (f->fd < 0) {
		fprintf(stderr, "read_file: Failed to open %s: %s\n", file_name, strerror(errno));
		error = "read_file() open failure";
		free(f);
		return 0;
	}
	struct stat st;
	if (fstat(f->fd, &st) < 0) {
		fprintf(stderr, "read_file: Failed to stat %s: %s\n", file_name, strerror(errno));
		error = "read_file() fstat failure";
		close(f->fd);
		free(f);
		return 0;
	}
	f->size = st.st_size;
	return f;

}

http_req *http_parse(char *str) {
	http_req *req = malloc(sizeof(http_req));
	if (!req) {
		error = "http_parse() malloc failure";
		return 0;
	}
	memset(req, 0, sizeof(http_req));
	char *p, *method_start = str, *url_start;

	for (p = str; *p && *p != ' '; p++);
	if (*p != ' ') {
		error = "http_parse() NOSPACE error";
		free(req);
		return 0;	
	}
	size_t method_len = p - method_start;
	if (method_len >= METHOD_LENGTH) method_len = METHOD_LENGTH - 1;
	
	strncpy(req->method, method_start, method_len);
	req->method[method_len] = '\0';

	url_start = p + 1;
	for (p = url_start; *p && *p != ' '; p++);
	if (*p != ' ') {
		error = "http_parse() NO2ndSPACE error";
		free(req);
		return 0;
	}
	size_t url_len = p - url_start;
	if (url_len >= URL_LENGTH) url_len = URL_LENGTH - 1;
	
	strncpy(req->url, url_start, url_len);
	req->url[url_len] = '\0';

	return req;
}

char *cli_read(int cli_fd) {
	char *buf = malloc(4096);
	if (!buf) {
		error = "cli_read() malloc failure";
		return 0;
	}
	size_t capacity = 4096, used = 0, max_size = 8192;
	while (used < max_size) {
		ssize_t n = read(cli_fd, buf + used, capacity - used - 1);
		if (n < 0) {
			error = "cli_read() read failure";
			free(buf);
			return 0;
		}
		if (n == 0) 
			break;
		used += n;
		buf[used] = '\0';
		if (strstr(buf, "\r\n\r\n")) 
			break;
		if (used >= capacity - 1) {
			if (capacity >= max_size) {
				error = "cli_read() request too large";
				free(buf);
				return 0;
			}
			capacity *= 2;
			char *temp = realloc(buf, capacity);
			if (!temp) {
				error = "cli_read() realloc failure";
				free(buf);
				return 0;
			}
			buf = temp;
		}
	}

	return used > 0 ? buf : 0;
}

char *get_mime_type(const char *url) {
	char *ext = strrchr(url, '.');
	if (!ext) return "application/octet-stream";
	if (strcasecmp(ext, ".png") == 0) return "image/png";
	if (strcasecmp(ext, ".jpg") == 0) return "image/jpg";
	if (strcasecmp(ext, ".gif") == 0) return "image/gif";
	if (strcasecmp(ext, ".webp") == 0) return "image/webp";
	if (strcasecmp(ext, ".ico") == 0) return "image/x-icon";	
	if (strcasecmp(ext, ".css") == 0) return "text/css";
	if (strcasecmp(ext, ".js") == 0) return "application/javascript";
	if (strcasecmp(ext, ".html") == 0) return "text/html";
		
	if (strcasecmp(ext, ".ttf") == 0 || strcasecmp(ext, ".woff") == 0 || strcasecmp(ext, ".woff2") == 0) return "font/woff2";
	if (strcasecmp(ext, ".json") == 0) return "application/json";
	if (strcasecmp(ext, ".txt") == 0) return "text/plain";
		
	return "application/octet-stream";
}

char *sanitize_input(char *body) {
	static char sanitized[1024];
	size_t i, j = 0;
	for (i = 0; body[i] && j < sizeof(sanitized) - 6; i++) {
		if (body[i] == '<') {
			strcpy(&sanitized[j], "&lt;");
			j += 4;
		} else if (body[i] == '>') {
			strcpy(&sanitized[j], "&gt;");
			j += 4;
		} else if (body[i] == '&') {
			strcpy(&sanitized[j], "&amp;");
			j += 5;
		} else if (body[i] == '"') {
			strcpy(&sanitized[j], "&quot;");
			j += 6;
		} else {
			sanitized[j++] = body[i];
		}
	}
	sanitized[j] = '\0';
	return sanitized;
}

int send_file(int cli_fd, char *mime_type, File *file) {
	char buf[8192];
	if (!file || file->fd < 0) return 0;
	off_t remaining = file->size;
	snprintf(buf, sizeof(buf),
			"HTTP/1.0 200 OK\r\n"
			"Content-Type: %s\r\n"
			"Content-Length: %lld\r\n"
			"Cache-Control: no-cache\r\n\r\n",
			mime_type, (long long)file->size);
	size_t header_len = strlen(buf), header_sent = 0;
	while (header_sent < header_len) {
		ssize_t x = write(cli_fd, buf + header_sent, header_len - header_sent);
		if (x <= 0) {
			error = "send_file() write header failure";
			return 0;
		}
		header_sent += x;
	}
	/* fprintf(stderr, "Streaming file %s (%lld bytes)\n", file->file_name, (long long)file->size); */
	while (remaining > 0) {
		size_t to_read = (remaining < sizeof(buf)) ? remaining : sizeof(buf);
		ssize_t n = read(file->fd, buf, to_read);
		if (n <= 0) {
			error = "send_file() read failure";
			fprintf(stderr, "%s :%s (tried %zu bytes)\n", error, strerror(errno), to_read);
			return 0;
		}
		size_t sent = 0;
		while (sent < n) {
			ssize_t x = write(cli_fd, buf + sent, n - sent);
			if (x <= 0) {
				error = "send_file() write content failure";
				fprintf(stderr, "%s : %s (tried %zu bytes)\n", error, strerror(errno), n - sent);
				return 0;
			}
			sent += x;
		}
		remaining -= n;
		/* fprintf(stderr, "Sent %zu bytes, %lld remaining\n", n, (long long)remaining); */
	}
	close(file->fd);
	free(file);
	return 1;
}

void url_decode(char *dst, const char *src, size_t dst_size) {
	size_t i = 0, j = 0;
	/* j for dst, i for src */
	while (src[i] && j < dst_size - 1) {
		if (src[i] == '%' && src[i + 1] && src[i + 2]) {
			char hex[3] = {src[i + 1], src[i + 2], '\0'};
			char decoded = (char)strtol(hex, NULL, 16);
			if (decoded) {
				dst[j++] = decoded;
				i += 3;
			} else {
				dst[j++] = src[i++];
			}

		} else {
			dst[j++] = src[i++];
		}	
	}
	dst[j] = '\0';
}

void clean_up(int cli_fd, ...) {
	va_list args;
	va_start(args, cli_fd);
	if (cli_fd >= 0) {
		if (close(cli_fd) == 1) {
			fprintf(stderr, "Failed to close cli_fd: %s\n", strerror(errno));
		}
	}
	void *ptr;
	while ((ptr = va_arg(args, void*)) != NULL) {
		free(ptr);
	}
	va_end(args);
}

char *read_client_body(int cli_fd, char *p) {
	char *content_len = strstr(p, "Content-Length: ");
	if (content_len) {
		int len = atoi(content_len + 16);	
		if (len > 0 && len <= 1024) {
			char *body = NULL;
			body = malloc(len + 1);
			if (!body) {
				error = "cli_connection body malloc failure";
				free(p);
				return 0;
			}
			size_t body_read = 0;
			char *body_start = strstr(p, "\r\n\r\n");
			if (body_start) {
				body_start += 4;
				size_t header_body_len = strlen(body_start);
				if (header_body_len > 0) {
					memcpy(body, body_start, header_body_len);
					body_read = header_body_len;
				}
			}
			while (body_read < len) {
				ssize_t n = read(cli_fd, body + body_read, len - body_read);
				if (n <= 0) {
					error = "cli_connection() body read failure";
					fprintf(stderr, "%s: %s\n", error, n < 0 ? strerror(errno) : "connection closed");
					free(body);
					body = NULL;
					break;
				}
				body_read += n;
			}
			if (body) {
				body[body_read] = '\0';
			}
			return body;
		}
	
	}
	return 0;
}

int cli_connection(int cli_fd) {	
	http_req *req;
	// char *res;
	char str[96];
	File *f;
	char *body = NULL;

	char *p = cli_read(cli_fd);
	if (!p) {
		fprintf(stderr, "%s\n", error);	
		close (cli_fd);
		return 0;
	}
	req = http_parse(p);
	if (!req) {
		fprintf(stderr, "%s\n", error);
		clean_up(cli_fd, p, NULL);
		return 0;
	}

	if (!strcmp(req->method, "POST")) {
		body = read_client_body(cli_fd, p);
	}

	if (!strcmp(req->method, "POST") && !strcmp(req->url, "/api/submit")) {
		if (body) {
			char buf[2048];
			char *sanitized = sanitize_input(body);

			snprintf(buf, sizeof(buf),
				"<html><body><h1>Submitted Data</h1><p>%s</p><a href='/'>Back</a></body></html>"
				, sanitized);

			if (!http_headers(cli_fd, 200))
				fprintf(stderr, "%s\n", error);			
			if (!http_response(cli_fd, "text/html", buf))
				fprintf(stderr, "%s\n", error);
		} else {
			if (!http_headers(cli_fd, 400))
				fprintf(stderr, "%s\n", error);
			if (!http_response(cli_fd, "text/plain", "No data submitted"))
				fprintf(stderr, "%s\n", error);
		}
		clean_up(cli_fd, body, p, req, NULL);
		return 1;
	}

	else if (!strcmp(req->method, "GET") && !strncmp(req->url, "/static/", 8)) {	
		fprintf(stderr, "Serving static file: %s\n", req->url);
	
		memset(str, 0, sizeof(str));
		snprintf(str, sizeof(str) - 1, "%s", req->url + 1);
		if (strstr(str, "..")) {
			if (!http_headers(cli_fd, 403))
				fprintf(stderr, "%s\n", error);
			if (!http_response(cli_fd, "text/plain", "Forbidden"))
				fprintf(stderr, "%s\n", error);
			clean_up(cli_fd, req, NULL);
			return 0;
		}
		f = read_file(str);
		if (!f) {
			fprintf(stderr, "Failed to read file: %s (%s)\n", str, error);
			
			if (!http_headers(cli_fd, 404))
				fprintf(stderr, "%s\n", error);
			if (!http_response(cli_fd, "text/plain", "File not found"))
				fprintf(stderr, "%s\n", error);
		} else {
			char *mime_type = get_mime_type(req->url);
			fprintf(stderr, "Serving file %s with MIME type %s\n", str, mime_type);
			
			if (!send_file(cli_fd, mime_type, f)) {
				if (!http_headers(cli_fd, 500))
					fprintf(stderr, "%s\n", error);
				if (!http_response(cli_fd, "text/plain", "Server error"))
					fprintf(stderr, "%s\n", error);
				if (f->fd >= 0) close(f->fd);
				free(f);
			}
		}
	}
	
	else if (!strcmp(req->method, "GET") && !strcmp(req->url, "/")) {	
		File *f = read_file("index.html");
		if (!f) {
			if (!http_headers(cli_fd, 404))
				fprintf(stderr, "%s\n", error);
			if (!http_response(cli_fd, "text/plain", "File not found"))
				fprintf(stderr, "%s\n", error);
		} else {
			char *mime_type = get_mime_type("index.html");
			if (!send_file(cli_fd, mime_type, f)) {
				if (!http_headers(cli_fd, 500))
					fprintf(stderr, "%s\n", error);
				if (!http_response(cli_fd, "text/plain", "Server error"))
					fprintf(stderr, "%s\n", error);
				if (f->fd >= 0) close(f->fd);
				free(f);
			}
		}

	}

	else if (!strcmp(req->url, "/api/user") && (!strcmp(req->method, "PATCH") || !strcmp(req->method, "DELETE"))) {
		if (!strcmp(req->method, "DELETE")) {
			strcpy(stored_name, "John Doe");
			stored_age = 30;
			if (!http_headers(cli_fd, 200))
				fprintf(stderr, "%s\n", error);
			if (!http_response(cli_fd, "text/plain", "User data deleted"))
				fprintf(stderr, "%s\n", error);
		} else {
			body = read_client_body(cli_fd, p);		
			if (!body) {
				if (!http_headers(cli_fd, 400))
					fprintf(stderr, "%s\n", error);
				if (!http_response(cli_fd, "text/plain", "No new input provided"))
					fprintf(stderr, "%s\n", error);
				clean_up(cli_fd, p, req, NULL);
				return 0;
			}
			
			
			char *name_start = strstr(body, "name=");
			char *age_start = strstr(body, "age=");
			char new_name[256] = {0};
			int new_age = 0;
			if (name_start) {
				name_start += 5;
				char *name_end = strchr(name_start, '&');
				size_t name_len = name_end ? (size_t)(name_end - name_start) : strlen(name_start);
				if (name_len >= sizeof(new_name)) name_len = sizeof(new_name) - 1;
				strncpy(new_name, name_start, name_len);
				new_name[name_len] = '\0';
				char decoded_name[256] = {0};
				url_decode(decoded_name, new_name, sizeof(decoded_name));
				strncpy(new_name, decoded_name, sizeof(new_name) - 1);
			}
			if (age_start) {
				age_start += 4;
				char *age_end = strchr(age_start, '&');
				size_t age_len = age_end ? (size_t)(age_end - age_start) : strlen(age_start);
				if (age_len > 10) {
					if (!http_headers(cli_fd, 400))

						fprintf(stderr, "%s\n", error);
					if (!http_response(cli_fd, "text/plain", "Invalid age format"))

						fprintf(stderr, "%s\n", error);
					clean_up(cli_fd, body, p, req, NULL);
					return 0;
				}
				new_age = atoi(age_start);

			}
			if (!name_start && !age_start) {
				if (!http_headers(cli_fd, 400))

					fprintf(stderr, "%s\n", error);
				if (!http_response(cli_fd, "text/plain", "Invalid data format"))

					fprintf(stderr, "%s\n", error);
				clean_up(cli_fd, body, p, req, NULL);
				return 0;
			}

			char sanitized_name[512] = {0};
			size_t j = 0;
			for (size_t i = 0; new_name[i] && j < sizeof(sanitized_name) - 2; i++) {
			    if (new_name[i] == '"' || new_name[i] == '\\') {
				sanitized_name[j++] = '\\';
				sanitized_name[j++] = new_name[i];
			    } else {
				sanitized_name[j++] = new_name[i];
			    }
			}
			sanitized_name[j] = '\0';
			
			if (name_start) strcpy(stored_name, sanitized_name);
			if (age_start) stored_age = new_age;
			char buf[1024];
		
			snprintf(buf, sizeof(buf), "{\"name\":\"%s\",\"age\":%d}", sanitized_name, stored_age);
			if (!http_headers(cli_fd, 200))
				fprintf(stderr, "%s\n", error);
			if (!http_response(cli_fd, "application/json", buf))
				fprintf(stderr, "%s\n", error);
		}
	}	
	
	else {
		if (!http_headers(cli_fd, 404))
				fprintf(stderr, "%s\n", error);
		if (!http_response(cli_fd, "text/plain", "Page Not Found"))
				fprintf(stderr, "%s\n", error);
	}

	clean_up(cli_fd, body, p, req, NULL);
	return 1;
}

int main(int argc, char *argv[]) {
	Tree *root = create_root_node();
	print_tree(root);
	return 0;



	struct sigaction sa;
	sa.sa_handler = sigint_handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		fprintf(stderr, "Failed to set SIGINT handler: %s\n", strerror(errno));
		return -1;
	}

	int serv_fd, cli_fd;
	const char *bind_addr = LOCAL_HOST;
	if (argc < 2) { 
		fprintf(stderr, "Usage: %s <listening port> [bind_addr]\n", argv[0]);
		return -1;
	}
	char *port_number = argv[1];
	serv_fd = server_init(bind_addr, atoi(port_number));
	if (serv_fd <= 0) {
		fprintf(stderr, "Server initialization failed: %s\n", error);
		return -1;	
	}
	printf("Listening on %s:%s\n", bind_addr, port_number); 
	
	while (keep_running) {
		cli_fd = cli_accept(serv_fd);	
		if (!cli_fd) {
			if (!keep_running) break;
			fprintf(stderr, "%s\n", error);
			continue;
		}
		printf("Incoming connection (%d/%d)\n", active_connections, MAX_CONNECTIONS);

	
		if (!fork()) {
			
			close(serv_fd);
			if (!cli_connection(cli_fd)) {
				fprintf(stderr, "%s\n", error);
			}
			exit(0);
		}
		close(cli_fd);
	}
	printf("Shutting down server...\n");
	if (close(serv_fd) == -1) {
		fprintf(stderr, "Failed to close server socket: %s\n", strerror(errno));
	}
	return 0;

}
