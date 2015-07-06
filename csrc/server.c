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
#include <time.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#define TEMPLATE "pagedata/page%d.pdt"
#define PWPATH "pagedata/master_password"

struct keyvalpair {
	char *key;
	char *value;
	struct keyvalpair *next;
};

struct session {
	unsigned long id;
	time_t regtime;
} last_session;

long hash_fnv(char *input) {
	long hash = 14695981039346656037;
	int len = strlen(input);
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
	else {
	if (strstr(token,"главная") || strstr(token,"home") || (str == NULL))
		res = 0;
	if (strstr(token,"техобслуживание") || strstr(token,"to"))
		res = 1;
	if (strstr(token,"прокат") || strstr(token,"rent"))
		res = 2;
	if (strstr(token,"акции") || strstr(token,"acts"))
		res = 3;
	}
	goto result;

error:
	res = -1;

result:
	return res;
}

void parse_post(struct keyvalpair *unit, char *post) {
	char *postelem = (char *)calloc(2000, sizeof(char));
	//unit = malloc(sizeof(struct keyvalpair));
	printf("Parse iteration\n");

	strcpy(postelem, strsep(&post,"&"));
	#ifdef __DEBUG__
	printf("'%s'\n",postelem);
	#endif

	char *key = (char *)calloc(strlen(postelem), sizeof(char));
	char *value = (char *)calloc(strlen(postelem), sizeof(char));
	strcpy(key, strsep(&postelem,"="));
	strcpy(value, postelem);
	#ifdef __DEBUG__
	printf("'%s'/'%s'\n",key, value);
	#endif


	unit->key = (char *)calloc(strlen(key), sizeof(char));
	strcpy(unit->key, key);
	unit->value = (char *)calloc(strlen(value), sizeof(char));
	strcpy(unit->value, value);
	#ifdef __DEBUG__
	printf("'%s'//'%s'; '%s'\n", unit->key, unit->value, post);
	#endif

	free(key);
	free(value);
	#ifdef __DEBUG__
	printf("Freed memory\n");
	#endif

	if (post != NULL) {
		unit->next = malloc(sizeof(struct keyvalpair));
		parse_post(unit->next, post);
	}
}

void postarg_lookup(struct keyvalpair *arg, char **buffer, const char *key) {
	#ifdef __DEBUG__
	printf("Lookup iteration: searching '%s' in %p\n", key, arg);
	printf("'%s'\n", arg->key);
	#endif
	if (strcmp(arg->key, key) == 0) {
		#ifdef __DEBUG__
		printf("Key found\n");
		#endif
		strcpy(*buffer, arg->value);
	} else if (arg->next != NULL) {
		postarg_lookup(arg->next, buffer, key);
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
		#ifdef __DEBUG__
		printf("Arguments parsed\n");
		#endif
		if (page_id == 110) {
			char *password = (char *)calloc(100, sizeof(char));
			#ifdef __DEBUG__
			printf("'%s' inside first keyvalpair\n", postargs.key);
			#endif
			postarg_lookup(&postargs, &password, "master_password"); //find password
			if (password != NULL) {
				long passhash = hash_fnv(password);
				#ifdef __DEBUG__
				printf("Received password '%s' hashed %ld\n",password, passhash);
				#endif
				free(password);

				FILE *pwd = fopen(PWPATH, "r");
				long actualhash = 0;
				fscanf(pwd, "%ld", &actualhash);
				fclose(pwd);

				#ifdef __DEBUG__
				printf("Actual hash is '%ld'\n",actualhash);
				long difference = passhash-actualhash;
				printf("Difference: %ld\n",difference);
				#endif

				if (passhash != actualhash) goto err;

				last_session.id = rand();
				time(&(last_session.regtime));

				char *cookie = (char *)calloc(200, sizeof(char));
				sprintf(cookie, "Session=%d", last_session.id);

				evhttp_add_header(evhttp_request_get_output_headers(req),
					"Set-Cookie", cookie);
				evhttp_add_header(evhttp_request_get_output_headers(req),
					"Refresh", "0; url=115");

				free(cookie);
			}
		}
		if (page_id > 110) {
			char *sidcookie = (char *)calloc(200, sizeof(char));
			sprintf(sidcookie, "Session=%d", last_session.id);
			time_t checktime;
			time(&checktime);
			struct evkayvalq *kv = evhttp_request_get_input_headers(req);

			#ifdef __DEBUG__
			printf("Session check:\n");
			printf("Last session ID: %ld\n", last_session.id);
			printf("Timestamp: %ld\n", last_session.regtime);
			printf("Received cookie: %s\n",evhttp_find_header(kv, "Cookie"));
			printf("Current time: %ld\n", checktime);
			#endif

			if (evhttp_find_header(kv, "Cookie") == NULL) goto err;

			if (!strstr(sidcookie, evhttp_find_header(kv, "Cookie")) || ((checktime-last_session.regtime)>300))
				goto err;
		}
		if (page_id == 140) {
			char *password = (char *)calloc(100, sizeof(char));
			#ifdef __DEBUG__
			printf("'%s' inside first keyvalpair\n", postargs.key);
			#endif
			postarg_lookup(&postargs, &password, "master_password"); //find password
			if (password != NULL) {
				unsigned long passhash = hash_fnv(password);
				#ifdef __DEBUG__
				printf("Received password '%s' hashed %ld\n",password, passhash);
				#endif
				free(password);

				FILE *pwf = fopen(PWPATH, "w");
				fprintf(pwf, "%ld", passhash);
				fclose(pwf);

				evhttp_add_header(evhttp_request_get_output_headers(req),
					"Refresh", "0; url=101");
			}
		}

		//postarg_free(&postargs);
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

	evbuffer_add_printf(evb,"<!DOCTYPE html><html><head><title>%s - АВТОМАМАША</title><meta charset=\"utf-8\"><link rel=\"stylesheet\" type=\"text/css\" href=\"templates/style.css\"><link rel=\"icon\" href=\"images/favicon.jpg\" sizes=\"16x16\" type=\"image/jpg\"><script type=\"text/javascript\" src=\"//vk.com/js/api/openapi.js?116\"></script></head><body><div id=\"header\"><a href=\"/\"><img id=\"mainlogo\" src=\"images/logo-wide.jpg\"></a><div id=\"mainnav\"><a id=\"homebut\" class=\"navbutton%s\" href=\"/\"><div class=\"butshade\">Главная</div></a><a id=\"techbut\" class=\"navbutton%s\" href=\"техобслуживание\"><div class=\"butshade\">Техобслуживание и ремонт</div></a><a id=\"rentbut\" class=\"navbutton%s\" href=\"прокат\"><div class=\"butshade\">Автопрокат</div></a><a id=\"actbut\" class=\"navbutton%s\" href=\"акции\"><div class=\"butshade\">Акции</div></a></div></div><div id=\"main\">%s</div><div id=\"footer\"></div></body></html>",
		title, act1, act2, act3, act4, content); //construct page

	free(title);
	free(content);

	evhttp_add_header(evhttp_request_get_output_headers(req),
		"Content-Type", "text/html");

	evhttp_send_reply(req, 200, "OK", evb);
	goto done;

err:
	evhttp_send_error(req, 404, "Not Found");

done:
	#ifdef __DEBUG__
	printf("Request served: %d\n", page_id);
	#endif
	if (dec) evhttp_uri_free(dec);
	if (decpath) free(decpath);
	if (evb) evbuffer_free(evb);
}

int main(int argc, char **argv) {
	struct event_base *base;
	struct evhttp *http;
	struct evhttp_bs *handle;

	unsigned short port = 2304;
	#ifndef __DEBUG__
	stdout = fopen("/var/log/server.log","a");
	#endif
	fclose(stdin);
	fclose(stderr);

	#ifndef __DEBUG__
	int status = daemon(0,1);
	if (status) {
		printf("Daemonize failure (%d, %d)\n", status, errno);
		return 1;
	}
	#endif

	last_session.id = 0;
	last_session.regtime = 0;

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