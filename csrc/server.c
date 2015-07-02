#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
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

#define TEMPLATE "pagedata/page%d.pdt"

int detect_pageid(char *str) {
	int res = 0;
	if (strstr(str, "страница") || strstr(str, "page")) {
		goto checkeach;
	}
checkeach:
	if (strstr(str,"главная") || strstr(str,"home") || (str == "/"))
		res = 0;
	if (strstr(str,"техобслуживание") || strstr(str,"to"))
		res = 1;
	if (strstr(str,"прокат") || strstr(str,"rent"))
		res = 2;
	if (strstr(str,"акции") || strstr(str,"acts"))
		res = 3;

result:
	return res;
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

	int page_id = detect_pageid(decpath);

	evb = evbuffer_new();
	char mode = 0;

	if (page_id>100) mode = 1;

	char *title = (char *)calloc(200, sizeof(char));
	char *fname = (char *)calloc(200, sizeof(char));
	char *content = (char *)calloc(200000, sizeof(char));

	int act = 0;
	switch (page_id) {
		case 0: act = 1; break;
		case 1: act = 2; break;
		case 2: act = 3; break;
		case 3: act = 4; break;
	}

	sprintf(fname, TEMPLATE, page_id);
	if (access(fname, R_OK) == 0) {
		FILE *pagefile = fopen(fname,"r");
		fgets(title, 199, pagefile);
		fgets(content, 199999, pagefile);
		fclose(pagefile);
	} else {
		strcpy(title,"404");
		strcpy(content,"<h1>Страница не найдена!</h1><p>Вернуться на <a href=\"/\">главную</a>?</p>");
		act = 1;
	}
	free(fname);

	char act1[6], act2[6], act3[6], act4[6];
	strcpy(act1, "");
	strcpy(act2, "");
	strcpy(act3, "");
	strcpy(act4, "");
	switch (act) {
		case 1: strcpy(act1, " act"); break;
		case 2: strcpy(act2, " act"); break;
		case 3: strcpy(act3, " act"); break;
		case 4: strcpy(act4, " act"); break;
	}

	evbuffer_add_printf(evb,"<!DOCTYPE html><html><head><title>%s - АВТОМАМАША</title><meta charset=\"utf-8\"><link rel=\"stylesheet\" type=\"text/css\" href=\"templates/style.css\"><link rel=\"icon\" href=\"images/favicon.jpg\" sizes=\"16x16\" type=\"image/jpg\"><script type=\"text/javascript\" src=\"//vk.com/js/api/openapi.js?116\"></script></head><body><div id=\"header\"><a href=\"/\"><img id=\"mainlogo\" src=\"images/logo-wide.jpg\"></a><div id=\"mainnav\"><a id=\"homebut\" class=\"navbutton%s\" href=\"/\"><div class=\"butshade\">Главная</div></a><a id=\"techbut\" class=\"navbutton%s\" href=\"техобслуживание\"><div class=\"butshade\">Техобслуживание и ремонт</div></a><a id=\"rentbut\" class=\"navbutton%s\" href=\"прокат\"><div class=\"butshade\">Аренда автомобилей</div></a><a id=\"actbut\" class=\"navbutton%s\" href=\"акции\"><div class=\"butshade\">Акции</div></a></div></div><div id=\"main\">%s</div><div id=\"footer\"></div></body></html>",
		title, act1, act2, act3, act4, content);

	free(title);
	free(content);

	evhttp_add_header(evhttp_request_get_output_headers(req),
		"Content-Type", "text/html");

	evhttp_send_reply(req, 200, "OK", evb);
	goto done;

err:
	evhttp_send_error(req, 404, "Not found");

done:
	printf("Request served: %s\n", decpath);
	if (dec) evhttp_uri_free(dec);
	if (decpath) free(decpath);
	if (evb) evbuffer_free(evb);
}

int main(int argc, char **argv) {
	struct event_base *base;
	struct evhttp *http;
	struct evhttp_bs *handle;

	unsigned short port = 2304;
	stdout = fopen("/var/log/server.log","a");
	fclose(stdin);
	fclose(stderr);

	int status = daemon(0,1);
	if (status) {
		printf("Daemonize failure (%d, %d)\n", status, errno);
		return 1;
	}

	printf("Server process successfully started.\n");

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