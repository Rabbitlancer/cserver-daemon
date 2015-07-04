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

struct keyvalpair {
	char *key;
	char *value;
	struct keyvalpair *next;
};

unsigned long hash_fnv(char *input, int len) {
	unsigned long hash = 14695981039346656037;
	for (int i = 0; i<len; i++) {
		hash ^= input[i];
		hash *= 1099511628211;
	}

	return hash;
}

int detect_pageid(char *str) { //figure out a page_id by URI; return -1 on error
	int res = 0;

	char *token = (char *)calloc(strlen(str), sizeof(char));
	strcpy(token, strsep(&str, "/"));
	strcpy(token, strsep(&str, "/"));

	if (strstr(token, "страница") || strstr(token, "page")) {
		strcpy(token, strsep(&str, "/"));
		if (token == NULL) goto error;
		res = atoi(token);
		goto result;
	}
	else if (strstr(token,"главная") || strstr(token,"home") || (str == NULL))
		res = 0;
	else if (strstr(token,"техобслуживание") || strstr(token,"to"))
		res = 1;
	else if (strstr(token,"прокат") || strstr(token,"rent"))
		res = 2;
	else if (strstr(token,"акции") || strstr(token,"acts"))
		res = 3;
	else goto error;
	goto result;

error:
	res = -1;

result:
	return res;
}

void parse_post(struct keyvalpair *unit, char *post) {
	char *postelem = (char *)calloc(2000, sizeof(char));
	//struct keyvalpair *unit = (struct keyvalpair *)calloc(1, sizeof(struct keyvalpair));

	strcpy(postelem, strsep(&post,"&"));
	printf("'%s'\n",postelem);

	char *key = (char *)calloc(strlen(postelem), sizeof(char));
	char *value = (char *)calloc(strlen(postelem), sizeof(char));
	strcpy(key, strsep(&postelem,"="));
	strcpy(value, postelem);
	printf("'%s'/'%s'\n",key, value);


	unit->key = (char *)calloc(strlen(key), sizeof(char));
	strcpy(unit->key, key);
	unit->value = (char *)calloc(strlen(value), sizeof(char));
	strcpy(unit->value, value);

	free(key);
	free(value);
	free(postelem);

	if (post != "") parse_post(unit->next, post);

	return;
}

char *postarg_lookup(struct keyvalpair *arg, const char *key) {
	if (arg->key == key) {
		return arg->value;
	} else if (arg->next != NULL) {
		return postarg_lookup(arg->next, key);
	} else {
		return NULL;
	}
}

void postarg_free(struct keyvalpair *unit) {
	if (unit->next != NULL) postarg_free(unit->next);
	free(unit->key);
	free(unit->value);
	free(unit);
	return;
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
	if (!path) path = "/"; //always add a slash

	char *decpath = evhttp_uridecode(path, 0, NULL);
	if (decpath == NULL) goto err;

	if (strstr(decpath,"..")) goto err; //just copied from example

	int page_id = detect_pageid(decpath);

	evb = evbuffer_new();

	if ((page_id>100) && (evhttp_request_get_command(req)==EVHTTP_REQ_POST)) { //enter POST mode
		char *req_text = (char *)calloc(2000, sizeof(char));
		evbuffer_copyout(evhttp_request_get_input_buffer(req),req_text,2000); //req_text now contains POST data
		struct keyvalpair postargs;
		parse_post(&postargs, req_text); //parse POST data
		if (page_id == 115) {
			char *password = (char *)calloc(100, sizeof(char));
			strcpy(password, postarg_lookup(&postargs, "master_password")); //find password
			unsigned long passhash = hash_fnv(password, strlen(password));
			printf("Received password '%s' hashed %d\n",password, passhash);
			free(password);
		}

		postarg_free(&postargs);
	}

	char *title = (char *)calloc(200, sizeof(char));
	char *fname = (char *)calloc(200, sizeof(char));
	char *content = (char *)calloc(200000, sizeof(char));

	int act = 0; //checking for active link
	switch (page_id) {
		case 0: act = 1; break;
		case 1: act = 2; break;
		case 2: act = 3; break;
		case 3: act = 4; break;
	}

	sprintf(fname, TEMPLATE, page_id);
	if (access(fname, R_OK) == 0) { //if file exists...
		FILE *pagefile = fopen(fname,"r");
		fgets(title, 199, pagefile);
		fgets(content, 199999, pagefile);
		fclose(pagefile);
	} else { //and if it doesn't. -1 automatically goes here
		strcpy(title,"404");
		strcpy(content,"<h1>Страница не найдена!</h1><p>Вернуться на <a href=\"/\">главную</a>?</p>");
		act = 1;
	}
	free(fname);

	char act1[6], act2[6], act3[6], act4[6]; //still preparing for active link
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
		title, act1, act2, act3, act4, content); //construct page

	free(title);
	free(content);

	evhttp_add_header(evhttp_request_get_output_headers(req),
		"Content-Type", "text/html");

	evhttp_send_reply(req, 200, "OK", evb);
	goto done;

err:
	evhttp_send_error(req, 404, "Not found");

done:
	printf("Request served: %d\n", page_id);
	if (dec) evhttp_uri_free(dec);
	if (decpath) free(decpath);
	if (evb) evbuffer_free(evb);
}

int main(int argc, char **argv) {
	struct event_base *base;
	struct evhttp *http;
	struct evhttp_bs *handle;

	unsigned short port = 2304;
	//stdout = fopen("/var/log/server.log","a");
	fclose(stdin); //commented for debug
	fclose(stderr);

	/*int status = daemon(0,1);
	if (status) {
		printf("Daemonize failure (%d, %d)\n", status, errno);
		return 1;
	}*/ //commented for debug

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