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
#define ACTPATH "pagedata/acts"
#define CARPATH "pagedata/cars"
#define MAILPATH "pagedata/mail"

#define __DEBUG__

char cachedmail[200];

struct keyvalpair {
	char *key;
	char *value;
	struct keyvalpair *next;
};

struct actcache {
	int id;
	char *title;
	char *descr;
	struct actcache *next;
	struct actcache *prev;
} *acts;

struct carcache {
	int id;
	int shortprice;
	int price;
	int longprice;
	int xlongprice;
	int pledge;
	char *name;
	char *opts;
	char *link;
	struct carcache *next;
	struct carcache *prev;
} *cars;

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

void makespaces(char **input) {
	int len = strlen(*input);
	#ifdef __DEBUG__
	printf("Removing spaces from '%s': ",*input);
	#endif
	for (int i = 0; i<len; i++) {
		if ((*input)[i] == '+')
			(*input)[i] = ' ';
		if ((*input)[i] == '\n')
			(*input)[i] = '\0';
	}
	#ifdef __DEBUG__
	printf("'%s'\n",*input);
	#endif
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
	if (strstr(token,"запись") || strstr(token,"signup"))
		res = 103;
	if (strstr(token,"обработано") || strstr(token,"processed"))
		res = 104;
	}
	goto result;

error:
	res = -1;

result:
	return res;
}

void parse_post(struct keyvalpair *unit, char *post) {
	char *postelem = (char *)calloc(20000, sizeof(char));
	#ifdef __DEBUG__
	printf("Parse iteration\n");
	#endif

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

	unit->key = evhttp_uridecode(key, 0, NULL);
	unit->value = evhttp_uridecode(value, 0, NULL);
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

int check_cookie(struct evhttp_request *req) {
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

	if (evhttp_find_header(kv, "Cookie") == NULL) return 0;
	if (!strstr(evhttp_find_header(kv, "Cookie"), sidcookie) || ((checktime-last_session.regtime)>300)) return 0;
	else return 1;
}

void cache_address() {
	FILE *fp = fopen(MAILPATH, "r");
	fscanf(fp, "%s", &cachedmail);
	#ifdef __DEBUG__
	printf("Cached address '%s'\n", cachedmail);
	#endif
	fclose(fp);
}

struct actcache *cache_acts_parse(FILE *rf, struct actcache *prev) {
	int id;
	char *title = (char *)calloc(500,sizeof(char));
	char *content = (char *)calloc(50000,sizeof(char));
	#ifdef __DEBUG__
	printf("Cache iteration\n");
	#endif

	if (fscanf(rf,"%d",&id) != EOF) {
		struct actcache *result = malloc(sizeof(struct actcache));
		char dump[500];	    //apparently, scanf does not progress the line reading in fgets, so we dump a single line into nothing
		fgets(dump,499,rf);

		fgets(title,499,rf);
		fgets(content,49999,rf);
		#ifdef __DEBUG__
		printf("Read (%d):\n%s\n%s\n----\n", id, title, content);
		#endif

		result->id = id;
		result->title = (char *)calloc(strlen(title), sizeof(char));
		result->descr = (char *)calloc(strlen(content), sizeof(char));
		result->prev = prev;
		result->next = NULL;

		makespaces(&title);
		makespaces(&content);
		strcpy(result->title, title);
		strcpy(result->descr, content);

		#ifdef __DEBUG__
		printf("Cached (%d):\n%s\n%s\n----\n", result->id, result->title, result->descr);
		#endif

		return result;
	} else return NULL;
}

struct carcache *cache_cars_parse(FILE *rf, struct carcache *prev) {
	int id, sprice, price, lprice, xlprice, plg;
	char *title = (char *)calloc(500,sizeof(char));
	char *opts = (char *)calloc(500,sizeof(char));
	char *link = (char *)calloc(500,sizeof(char));
	#ifdef __DEBUG__
	printf("Cache iteration\n");
	#endif

	if (fscanf(rf,"%d %d %d %d %d %d",&id,&sprice,&price,&lprice,&xlprice,&plg) != EOF) {
		struct carcache *result = malloc(sizeof(struct carcache));
		char dump[500];	    //apparently, scanf does not progress the line reading in fgets, so we dump a single line into nothing
		fgets(dump,499,rf);

		fgets(title,499,rf);
		fgets(opts,499,rf);
		fgets(link,499,rf);
		#ifdef __DEBUG__
		printf("Read (%d):\n%d %d %d %d %d\n%s\n%s\n%s\n----\n", id, sprice, price, lprice, xlprice, plg, title, opts, link);
		#endif

		result->id = id;
		result->shortprice = sprice;
		result->price = price;
		result->longprice = lprice;
		result->xlongprice = xlprice;
		result->pledge = plg;
		result->name = (char *)calloc(strlen(title), sizeof(char));
		result->opts = (char *)calloc(strlen(opts), sizeof(char));
		result->link = (char *)calloc(strlen(link), sizeof(char));
		result->prev = prev;
		result->next = NULL;

		makespaces(&title);
		makespaces(&opts);
		makespaces(&link);
		strcpy(result->name, title);
		strcpy(result->opts, opts);
		strcpy(result->link, link);

		#ifdef __DEBUG__
		printf("Cached (%d):\n%d %d %d %d %d\n%s\n%s\n%s\n----\n", result->id, result->shortprice, result->price, result->longprice, result->xlongprice, result->pledge, result->name, result->opts, result->link);
		#endif

		return result;
	} else return NULL;
}

void cache_acts() {
	FILE *fp = fopen(ACTPATH, "r");
	#ifdef __DEBUG__
	printf("Caching base node\n");
	#endif
	acts = cache_acts_parse(fp, NULL);
	struct actcache *ptr = acts;

	while (ptr != NULL) {
		#ifdef __DEBUG__
		printf("Caching...\nAppending to %d\n", ptr->id);
		#endif
		ptr->next = cache_acts_parse(fp, ptr);
		ptr = ptr->next;
	}

	fclose(fp);
}

void cache_cars() {
	FILE *fp = fopen(CARPATH, "r");
	#ifdef __DEBUG__
	printf("Caching base node\n");
	#endif
	cars = cache_cars_parse(fp, NULL);
	struct carcache *ptr = cars;

	while (ptr != NULL) {
		#ifdef __DEBUG__
		printf("Caching...\nAppending to %d\n", ptr->id);
		#endif
		ptr->next = cache_cars_parse(fp, ptr);
		ptr = ptr->next;
	}

	fclose(fp);
}

void stash_acts() {
	FILE *fp = fopen(ACTPATH, "w");
	struct actcache *ptr = acts;

	while (ptr != NULL) {
		fprintf(fp,"%d\n%s\n%s",ptr->id,ptr->title,ptr->descr);
		ptr = ptr->next;
		if (ptr != NULL) fputc('\n', fp);
	}

	#ifdef __DEBUG__
	printf("Cache stashed\n");
	#endif

	fclose(fp);
}

void stash_cars() {
	FILE *fp = fopen(CARPATH, "w");
	struct carcache *ptr = cars;

	while (ptr != NULL) {
		fprintf(fp,"%d %d %d %d %d %d\n%s\n%s\n%s",ptr->id, ptr->shortprice, ptr->price, ptr->longprice, ptr->xlongprice, ptr->pledge, ptr->name, ptr->opts, ptr->link);
		ptr = ptr->next;
		if (ptr != NULL) fputc('\n', fp);
	}

	#ifdef __DEBUG__
	printf("Cache stashed\n");
	#endif

	fclose(fp);
}

void remove_from_acts(int id) {
	struct actcache *ptr = acts;

	#ifdef __DEBUG__
	printf("Removing element %d... ",id);
	#endif

	while (ptr != NULL) {
		if (ptr->id == id) {
			#ifdef __DEBUG__
			printf("found... ");
			#endif
			if (ptr->prev != NULL) ptr->prev->next = ptr->next;
			if (ptr->next != NULL) ptr->next->prev = ptr->prev;
			free(ptr->title);
			free(ptr->descr);
			if (ptr == acts) acts = ptr->next;
			free(ptr);
			goto done;
		} else ptr=ptr->next;
	}

done:
	#ifdef __DEBUG__
	printf("removed\n");
	#endif

	return;
}

void remove_from_cars(int id) {
	struct carcache *ptr = cars;

	#ifdef __DEBUG__
	printf("Removing element %d... ",id);
	#endif

	while (ptr != NULL) {
		if (ptr->id == id) {
			#ifdef __DEBUG__
			printf("found... ");
			#endif
			if (ptr->prev != NULL) ptr->prev->next = ptr->next;
			if (ptr->next != NULL) ptr->next->prev = ptr->prev;
			free(ptr->name);
			free(ptr->opts);
			free(ptr->link);
			if (ptr == cars) cars = ptr->next;
			free(ptr);
			goto done;
		} else ptr=ptr->next;
	}

done:
	#ifdef __DEBUG__
	printf("removed\n");
	#endif

	return;
}

int getactid() {
	int id = 0;
	struct actcache *ptr;

lookupid:
	ptr = acts;
	while (ptr!=NULL) {
		if (ptr->id == id) {
			id++;
			goto lookupid;
		} else ptr = ptr->next;
	}

	return id;
}

int getcarid() {
	int id = 0;
	struct carcache *ptr;

lookupid:
	ptr = cars;
	while (ptr!=NULL) {
		if (ptr->id == id) {
			id++;
			goto lookupid;
		} else ptr = ptr->next;
	}

	return id;
}

void insert_acts(int pos, char *title, char *text) {
	#ifdef __DEBUG__
	printf("Inserting '%s'/'%s' at position %d\n", title, text, pos);
	#endif
	if (acts == NULL) {
		#ifdef __DEBUG__
		printf("Creating new base node!\n");
		#endif
		acts = malloc(sizeof(struct actcache));
		acts->id = 0;
		acts->prev = NULL;
		acts->next = NULL;
		acts->title = (char *)calloc(strlen(title),sizeof(char));
		acts->descr = (char *)calloc(strlen(text),sizeof(char));
		strcpy(acts->title, title);
		strcpy(acts->descr, text);
	} else {
		struct actcache *ptr = acts;
		#ifdef __DEBUG__
		printf("Looking up position...\n");
		#endif
		if (pos>0) {
			while ((ptr->next != NULL) && (pos>0)) {
				ptr = ptr->next;
				pos--;
			}
			#ifdef __DEBUG__
			printf("Current pointer at: %d\n", ptr->id);
			#endif
			struct actcache *new = malloc(sizeof(struct actcache));
			new->id = getactid();
			new->title = (char *)calloc(strlen(title),sizeof(char));
			new->descr = (char *)calloc(strlen(text),sizeof(char));
			strcpy(new->title, title);
			strcpy(new->descr, text);
			new->prev = ptr;
			new->next = ptr->next;
			if (ptr->next != NULL) ptr->next->prev = new;
			if (ptr != NULL) ptr->next = new;
		} else {
			#ifdef __DEBUG__
			printf("Swapping base node\n");
			#endif
			ptr = malloc(sizeof(struct actcache));
			ptr->id = getactid();
			ptr->title = (char *)calloc(strlen(title),sizeof(char));
			ptr->descr = (char *)calloc(strlen(text),sizeof(char));
			strcpy(ptr->title, title);
			strcpy(ptr->descr, text);
			ptr->prev = NULL;
			ptr->next = acts;
			acts->prev = ptr;
			acts = ptr;
		}
	}
	#ifdef __DEBUG__
	printf("Inserted.\n");
	#endif
}

void insert_cars(int pos, char *name, char *opts, char *link, int xlp, int lp, int p, int sp, int plg) {
	#ifdef __DEBUG__
	printf("Inserting '%s' at position %d\n", name, pos);
	#endif
	if (cars == NULL) {
		#ifdef __DEBUG__
		printf("Creating new base node!\n");
		#endif
		cars = malloc(sizeof(struct carcache));
		cars->id = 0;
		cars->prev = NULL;
		cars->next = NULL;
		cars->name = (char *)calloc(strlen(name),sizeof(char));
		cars->opts = (char *)calloc(strlen(opts),sizeof(char));
		cars->link = (char *)calloc(strlen(link),sizeof(char));
		cars->xlongprice = xlp;
		cars->longprice = lp;
		cars->price = p;
		cars->shortprice = sp;
		cars->pledge = plg;
		strcpy(cars->name, name);
		strcpy(cars->opts, opts);
		strcpy(cars->link, link);
	} else {
		struct carcache *ptr = cars;
		#ifdef __DEBUG__
		printf("Looking up position...\n");
		#endif
		if (pos>0) {
			while ((ptr->next != NULL) && (pos>0)) {
				ptr = ptr->next;
				pos--;
			}
			#ifdef __DEBUG__
			printf("Current pointer at: %d\n", ptr->id);
			#endif
			struct carcache *new = malloc(sizeof(struct carcache));
			new->id = getcarid();
			new->name = (char *)calloc(strlen(name),sizeof(char));
			new->opts = (char *)calloc(strlen(opts),sizeof(char));
			new->link = (char *)calloc(strlen(link),sizeof(char));
			new->xlongprice = xlp;
			new->longprice = lp;
			new->price = p;
			new->shortprice = sp;
			new->pledge = plg;
			strcpy(new->name, name);
			strcpy(new->opts, opts);
			strcpy(new->link, link);
			new->prev = ptr;
			new->next = ptr->next;
			if (ptr->next != NULL) ptr->next->prev = new;
			if (ptr != NULL) ptr->next = new;
		} else {
			#ifdef __DEBUG__
			printf("Swapping base node\n");
			#endif
			ptr = malloc(sizeof(struct carcache));
			ptr->id = getcarid();
			ptr->name = (char *)calloc(strlen(name),sizeof(char));
			ptr->opts = (char *)calloc(strlen(opts),sizeof(char));
			ptr->link = (char *)calloc(strlen(link),sizeof(char));
			ptr->xlongprice = xlp;
			ptr->longprice = lp;
			ptr->price = p;
			ptr->shortprice = sp;
			ptr->pledge = plg;
			strcpy(ptr->name, name);
			strcpy(ptr->opts, opts);
			strcpy(ptr->link, link);
			ptr->prev = NULL;
			ptr->next = cars;
			cars->prev = ptr;
			cars = ptr;
		}
	}
	#ifdef __DEBUG__
	printf("Inserted.\n");
	#endif
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
		char *req_text = (char *)calloc(20000, sizeof(char));
		evbuffer_copyout(evhttp_request_get_input_buffer(req),req_text,20000); //req_text now contains POST data
		struct keyvalpair postargs;
		parse_post(&postargs, req_text); //parse POST data
		#ifdef __DEBUG__
		printf("Arguments parsed\n");
		#endif
		if (page_id == 104) {
			char *command = (char *)calloc(200000, sizeof(char));
			char *name = (char *)calloc(500, sizeof(char));
			char *mail = (char *)calloc(500, sizeof(char));
			char *car = (char *)calloc(500, sizeof(char));
			char *vin = (char *)calloc(500, sizeof(char));
			char *phone = (char *)calloc(500, sizeof(char));
			char *text = (char *)calloc(50000, sizeof(char));

			postarg_lookup(&postargs, &name, "username");
			postarg_lookup(&postargs, &mail, "email");
			postarg_lookup(&postargs, &car, "carname");
			postarg_lookup(&postargs, &vin, "vin");
			postarg_lookup(&postargs, &phone, "mobphone");
			postarg_lookup(&postargs, &text, "request");
			makespaces(&text);

			sprintf(command, "echo \"Имя: %s\nE-mail: %s\nАвтомобиль: %s\nVIN: %s\nТелефон: %s\nТекст заявки: %s\n\" | mail -s \"Заявка\" %s", name, mail, car, vin, phone, text, cachedmail);
			system(command);
			#ifdef __DEBUG__
			printf("Send command executed.\n");
			#endif

			free(text);
			free(phone);
			free(vin);
			free(car);
			free(mail);
			free(name);
			free(command);
		}
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
			if (check_cookie(req) == 0) goto err;	
		}
		if (page_id == 118) {
			char *buf = (char *)calloc(100, sizeof(char));
			postarg_lookup(&postargs, &buf, "id");

			int remid = atoi(buf);
			free(buf);
			remove_from_cars(remid);
			stash_cars();

			evhttp_add_header(evhttp_request_get_output_headers(req),
					"Refresh", "0; url=117");
		}
		if (page_id == 119) {
			char *buf = (char *)calloc(100, sizeof(char));
			postarg_lookup(&postargs, &buf, "pos");
			int pos = atoi(buf);
			postarg_lookup(&postargs, &buf, "xlp");
			int xlp = atoi(buf);
			postarg_lookup(&postargs, &buf, "lp");
			int lp = atoi(buf);
			postarg_lookup(&postargs, &buf, "p");
			int p = atoi(buf);
			postarg_lookup(&postargs, &buf, "sp");
			int sp = atoi(buf);
			postarg_lookup(&postargs, &buf, "plg");
			int plg = atoi(buf);
			free(buf);

			char *name = (char *)calloc(500, sizeof(char));
			char *link = (char *)calloc(500, sizeof(char));
			char *opts = (char *)calloc(500, sizeof(char));
			postarg_lookup(&postargs, &name, "name");
			postarg_lookup(&postargs, &link, "link");
			postarg_lookup(&postargs, &opts, "opts");
			makespaces(&name);
			makespaces(&link);
			makespaces(&opts);

			insert_cars(pos,name,opts,link,xlp,lp,p,sp,plg);
			stash_cars();

			evhttp_add_header(evhttp_request_get_output_headers(req),
					"Refresh", "0; url=117");
		}
		if (page_id == 122) {
			char *buf = (char *)calloc(100, sizeof(char));
			postarg_lookup(&postargs, &buf, "id");

			int remid = atoi(buf);
			free(buf);
			remove_from_acts(remid);
			stash_acts();

			evhttp_add_header(evhttp_request_get_output_headers(req),
					"Refresh", "0; url=121");
		}
		if (page_id == 123) {
			char *buf = (char *)calloc(100, sizeof(char));
			postarg_lookup(&postargs, &buf, "pos");
			int pos = atoi(buf);
			free(buf);

			char *title = (char *)calloc(500, sizeof(char));
			char *cont = (char *) calloc(50000, sizeof(char));

			postarg_lookup(&postargs, &title, "title");
			postarg_lookup(&postargs, &cont, "descr");
			makespaces(&title);
			makespaces(&cont);

			insert_acts(pos, title, cont);
			stash_acts();

			evhttp_add_header(evhttp_request_get_output_headers(req),
					"Refresh", "0; url=121");
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
		if (page_id == 152) {
			char *addr = (char *)calloc(100, sizeof(char));
			#ifdef __DEBUG__
			printf("'%s' inside first keyvalpair\n", postargs.key);
			#endif
			postarg_lookup(&postargs, &addr, "callbackaddress"); //find password
			if (addr != NULL) {
				#ifdef __DEBUG__
				printf("Received address '%s'\n",addr);
				#endif

				FILE *pwf = fopen(MAILPATH, "w");
				fprintf(pwf, "%s", addr);
				fclose(pwf);
				free(addr);

				evhttp_add_header(evhttp_request_get_output_headers(req),
					"Refresh", "0; url=101");
			}
		}

		//postarg_free(&postargs);
	}

	if (page_id>200) {
		if (check_cookie(req) == 0) goto err;
		if (page_id == 201) {

		}
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

	if (page_id == 2) {
		strcpy(title,"Автопрокат");
		strcpy(content,"<table class=\"cars\"><tbody><tr><th rowspan=\"2\" class=\"table-car\">Автомобиль</th><th rowspan=\"2\" class=\"table-opts\">Опции</th><th colspan=\"4\">Цена за сутки (руб.)</th><th rowspan=\"2\" class=\"table-pledge\">Залог</th></tr><tr><th class=\"table-xlp\">От 14 дней</th><th class=\"table-lp\">От 7 до 13</th><th class=\"table-p\">От 4 до 6</th><th class=\"table-sp\">До 3 дней</th></tr>");
		struct carcache *ptr = cars;
		char line[50000];
		if (ptr == NULL) {
			strcat(content,"<tr><td colspan=\"7\">На данный момент машины отсутствуют!</td></tr>");
		}
		while (ptr != NULL) {
			sprintf(line,"<tr><td class=\"table-car\"><img class=\"popimager\" src=\"%s\" width=\"100%%\"><p>%s</p></td><td class=\"table-opts\"><p>%s</p></td><td class=\"table-xlp\"><p>%d</p></td><td class=\"table-lp\"><p>%d</p></td><td class=\"table-p\"><p>%d</p></td><td class=\"table-sp\"><p>%d</p></td><td class=\"table-pledge\"><p>%d</p></td></tr>",ptr->link,ptr->name,ptr->opts,ptr->xlongprice,ptr->longprice,ptr->price,ptr->shortprice,ptr->pledge);
			strcat(content,line);
			strcpy(line,"");
			ptr = ptr->next;
		}
		strcat(content,"</tbody></table>");
	} else if (page_id == 3) {
		strcpy(title,"Акции");
		struct actcache *ptr = acts;
		char line[50000];
		strcpy(content,"");
		while (ptr != NULL) {
			sprintf(line, "<h2>%s</h2><p>%s</p>", ptr->title, ptr->descr);
			strcat(content,line);
			strcpy(line,"");
			ptr = ptr->next;
		}
	} else if (page_id == 121) {
		strcpy(title,"Редактирование акций");
		struct actcache *ptr = acts;
		char line[50000];
		strcpy(content,"");
		while (ptr != NULL) {
			sprintf(line, "<h3>%d - %s</h3><p>%s</p>", ptr->id, ptr->title, ptr->descr);
			strcat(content,line);
			strcpy(line,"");
			ptr = ptr->next;
		}
		strcat(content,"<form action=\"122\" method=\"post\"><p>Удалить акцию:</p><input type=\"text\" value=\"номер\" name=\"id\"><input type=\"submit\" value=\"Удалить\"></form>");
		strcat(content,"<form action=\"123\" method=\"post\"><p>Добавить акцию:</p><input type=\"text\" value=\"порядок\" name=\"pos\"><input type=\"text\" value=\"название\" name=\"title\"><br><textarea name=\"descr\" cols=\"80\" rows=\"10\">текст (не использовать перенос строки!)</textarea><br><input type=\"submit\" value=\"Добавить\"><p>ВНИМАНИЕ: не используйте символ переноса строки. Чтобы перенести строку, используйте символы &lt;br&gt;</p>Порядок указывает, на каком месте будет расположена акция. 0 означает первое место, 1 - второе и т.д.<p></p></form>");
	} else if (page_id == 117) {
		strcpy(title,"Редактирование проката");
		strcpy(content,"<p>Чтобы добавить фотографию автомобиля:</p><p>- используйте любой хостинг изображений, например, <a href=\"http://tinypic.com\">tinypic.com</a></p><p>- вставьте полученную ссылку в поле &quot;фотография&quot;</p>");
		struct carcache *ptr = cars;
		char line[50000];
		while (ptr != NULL) {
			sprintf(line,"<h2>%d - %s</h2><img src=\"%s\">",ptr->id,ptr->name,ptr->link);
			strcat(content,line);
			strcpy(line,"");
			ptr = ptr->next;
		}
		strcat(content,"<form action=\"118\" method=\"post\"><p>Удалить автомобиль:</p><input type=\"text\" value=\"номер\" name=\"id\"><input type=\"submit\" value=\"Удалить\"></form>");
		strcat(content,"<form action=\"119\" method=\"post\"><p>Добавить автомобиль:</p><input type=\"text\" value=\"порядок\" name=\"pos\"><input type=\"text\" value=\"название\" name=\"name\"><input type=\"text\" value=\"фотография\" name=\"link\"><input type=\"text\" value=\"опции\" name=\"opts\"><input type=\"text\" value=\"цена за 14+ дней\" name=\"xlp\"><input type=\"text\" value=\"7-14\" name=\"lp\"><input type=\"text\" value=\"3-6\" name=\"p\"><input type=\"text\" value=\"1-3\" name=\"sp\"><input type=\"text\" value=\"залог\" name=\"plg\"><input type=\"submit\" value=\"Добавить\"></form>");
	} else {
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

	evbuffer_add_printf(evb,"<!DOCTYPE html><html><head><title>%s - АВТОМАМАША</title><meta name=\"google-site-verification\" content=\"9AnsCoKYzpX1teVTI26Dl-owW-QzRleNG23qI3uw6-Q\" /><link href='http://fonts.googleapis.com/css?family=Roboto&subset=latin,cyrillic' rel='stylesheet' type='text/css'><style>body {font-family: 'Roboto', sans-serif;}</style><script src=\"https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js\"></script><script>(function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){(i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)})(window,document,'script','//www.google-analytics.com/analytics.js','ga');ga('create', 'UA-66174749-1', 'auto');ga('send', 'pageview');</script><script src=\"templates/pagescripts.js\"></script><meta charset=\"utf-8\"><link rel=\"stylesheet\" type=\"text/css\" href=\"templates/style.css\"><link rel=\"icon\" href=\"images/favicon.jpg\" sizes=\"16x16\" type=\"image/jpg\"><script type=\"text/javascript\" src=\"//vk.com/js/api/openapi.js?116\"></script></head><body><div id=\"header\"><a href=\"/\"><img id=\"mainlogo\" src=\"images/logo-wide.jpg\"></a><div id=\"mainnav\"><a id=\"homebut\" class=\"navbutton%s\" href=\"/\"><div class=\"butshade\">Главная</div></a><a id=\"techbut\" class=\"navbutton%s\" href=\"техобслуживание\"><div class=\"butshade\">Техобслуживание и ремонт</div></a><a id=\"rentbut\" class=\"navbutton%s\" href=\"прокат\"><div class=\"butshade\">Автопрокат</div></a><a id=\"actbut\" class=\"navbutton%s\" href=\"акции\"><div class=\"butshade\">Акции</div></a></div></div><div id=\"main\">%s</div><div id=\"footer\"><script type=\"text/javascript\">var sc_project=10568679; var sc_invisible=0; var sc_security=\"b5e4ee47\"; var scJsHost = ((\"https:\" == document.location.protocol) ? \"https://secure.\" : \"http://www.\");document.write(\"<sc\"+\"ript type='text/javascript' src='\" +scJsHost+\"statcounter.com/counter/counter.js'></\"+\"script>\");</script></div></body></html>",
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
	acts = NULL;
	cars = NULL;
	#ifndef __DEBUG__
	stdout = fopen("/var/log/server.log","a");
	#endif
	fclose(stdin);
	fclose(stderr);

	cache_address();
	cache_acts();
	cache_cars();

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