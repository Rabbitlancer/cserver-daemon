#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

//the following lines, including guess_content_type(),
//were taken from open-source example of libevent
//http-server.c

static const struct table_entry {
	const char *extension;
	const char *content_type;
} content_type_table[] = {
	{ "txt", "text/plain" },
	{ "c", "text/plain" },
	{ "h", "text/plain" },
	{ "html", "text/html" },
	{ "htm", "text/htm" },
	{ "css", "text/css" },
	{ "gif", "image/gif" },
	{ "jpg", "image/jpeg" },
	{ "jpeg", "image/jpeg" },
	{ "png", "image/png" },
	{ "pdf", "application/pdf" },
	{ "ps", "application/postsript" },
	{ NULL, NULL },
};

/* Try to guess a good content-type for 'path' */
static const char *
guess_content_type(const char *path)
{
	const char *last_period, *extension;
	const struct table_entry *ent;
	last_period = strrchr(path, '.');
	if (!last_period || strchr(last_period, '/'))
		goto not_found; /* no exension */
	extension = last_period + 1;
	for (ent = &content_type_table[0]; ent->extension; ++ent) {
		if (!evutil_ascii_strcasecmp(ent->extension, extension))
			return ent->content_type;
	}

not_found:
	return "application/misc";
}

struct evbuffer *construct_document(struct evbuffer *buf, int id) {
	buf = evbuffer_new();

	return buf;
}

static void send_document(struct evhttp_request *req, void *arg) {
	const char *uri = evhttp_request_get_uri(req);
	struct evhttp_uri *dec = NULL;
	struct evbuffer *evb = NULL;

	dec = evhttp_uri_parse(uri);
	if (!dec) {
		evhttp_send_error(req, HTTP_BADREQUEST, 0);
		return;
	}

	const char *path = evhttp_uri_get_path(dec);
	if (!path) path = "/";

	char *decpath = evhttp_uridecode(path, 0, NULL);
	if (decpath == NULL) goto err;

	if (strstr(decpath,"..")) goto err;

	construct_document(evb, 1);

	evhttp_send_reply(req, 200, "OK", evb);
	goto done;

err:
	evhttp_send_error(req, 404, "Not found");

done:
	if (dec) evhttp_uri_free(dec);
	if (decpath) free(decpath);
	if (evb) evbuffer_free(evb);
}

int main(int argc, char **argv) {
	struct event_base *base;
	struct evhttp *http;
	struct evhttp_bs *handle;

	unsigned short port = 2304;
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		printf("SIGPIPE\n");
		return 1;
	}

	base = event_base_new();
	if (!base) {
		printf("Error creating event_base\n");
		return 1;
	}

	http = evhttp_new(base);
	if (!http) {
		printf("Error creating http server\n");
		return 1;
	}

	evhttp_set_gencb(http, send_document, NULL);

	handle = evhttp_bind_socket_with_handle(http, "localhost", port);
	if (!handle) {
		printf("Couldn't bind port %d\n",port);
		return 1;
	}

	event_base_dispatch(base);

	return 0;
}