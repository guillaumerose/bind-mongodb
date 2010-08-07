/*
 * Copyright (C) 2010 Guillaume Rose <guillaume.rose@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * A simple database driver that uses MongoDB
 */

#include <config.h>

#include <string.h>
#include <stdio.h>
#include <time.h>

#include <isc/mem.h>
#include <isc/print.h>
#include <isc/result.h>
#include <isc/util.h>
#include <isc/thread.h>

#include <dns/sdb.h>

#include <named/globals.h>

#include "mongodb.h"
#include "mongo.h"

#define	MONGO_STRING_LENGTH	8196


typedef struct _dbinfo {
    char *host;
    char *port;
    char *base;
    
    char *search;
    
    char *dns;
    char *ip;
    
    char *request_type;
    
    char *search_prefix;
    char *result_suffix;
    
    char *zone;
} dbinfo_t;

typedef struct list {
	char *zone;
	mongo_connection *conn;
	mongo_connection_options opts;
	struct list * next;
} item;

static dns_sdbimplementation_t *mongodb = NULL;
static item *connection_list = NULL;


static item *enlister(item *head, char *zone, mongo_connection *conn, mongo_connection_options opts) {
	item *current = malloc(sizeof(item));
	current->zone = zone;
	current->conn = conn;
	current->opts = opts;
	current->next = NULL;
	
	if (head == NULL) {
		return current;
	}

	item *iterator = head;
	while(iterator->next != NULL) {
		iterator = iterator->next;
	}
	
	iterator->next = current;
	return head;
}

static item *delister(item *head, char *zone) {
	if (head == NULL) {
		return NULL;
	}
	
	item *precedent = NULL;
	item *courant = head;
	while(courant->next != NULL && strcmp(courant->zone, zone) != 0) {
		precedent = courant;
		courant = courant->next;
	}
	
	if (precedent != NULL && strcmp(courant->zone, zone) == 0) {
		precedent->next = courant->next;
	} else if (precedent == NULL && strcmp(courant->zone, zone) == 0) {
		return courant->next;
	}
	return head;
}

static item *chercher(item *head, char *i) {
	item *iterator = head;
	while(iterator != NULL && strcmp(iterator->zone, i) != 0) {
		iterator = iterator->next;
	}
	return iterator;
}

static void mongodb_lock(int what) {
	static isc_mutex_t lock;

	switch (what) {
	case 0:
		isc_mutex_init(&lock);
		break;
	case 1:
		LOCK(&lock);
		break;
	case -1:
		UNLOCK(&lock);
		break;
	}
}

int
mongo_start(void *dbdata) 
{	
	mongo_connection *conn = malloc(2 * sizeof(mongo_connection));
	mongo_connection_options opts;

	dbinfo_t *dbi = (dbinfo_t *) dbdata;
	
	strncpy(opts.host, dbi->host, 255);
	opts.host[254] = '\0';
	opts.port = atoi(dbi->port);
	
	if (mongo_connect(conn, &opts)){
		printf("Failed to connect to %s:%s\n", dbi->host, dbi->port);
		return 0;
	}
	
	mongodb_lock(1);
	connection_list = delister(connection_list, dbi->zone);
	connection_list = enlister(connection_list, dbi->zone, conn, opts);
	mongodb_lock(-1);
	
	printf("Connected to MongoDB\n");
	return 1;
}

void 
find_in_array(bson_iterator *it, const char *key_ref, const char *value_ref, const char *key_needed, char *value_needed) 
{
	char value_ref_found[MONGO_STRING_LENGTH];
	char value_needed_found[MONGO_STRING_LENGTH];

	bson_iterator i;
	
	while(bson_iterator_next(it)) {
		switch(bson_iterator_type(it)){
			case bson_string:
				if (strcmp(bson_iterator_key(it), key_ref) == 0)
					strcpy(value_ref_found, bson_iterator_string(it));
				if (strcmp(bson_iterator_key(it), key_needed) == 0)
					strcpy(value_needed_found, bson_iterator_string(it));
				break;
			case bson_object:
			case bson_array:
				bson_iterator_init(&i, bson_iterator_value(it));
				find_in_array(&i, key_ref, value_ref, key_needed, value_needed);
				break;
			default:
				break;
		}
	}
	
	if (strcmp(value_ref_found, value_ref) == 0)
		strcpy(value_needed, value_needed_found);
}

int 
find_bind_options(void *dbdata, const char *mac, char *dhcp) 
{
	dbinfo_t *dbi = (dbinfo_t *) dbdata;
	
	mongodb_lock(1);
	item *connection = chercher(connection_list, dbi->zone);
	mongodb_lock(-1);
	
	mongo_connection *conn = connection->conn;

	bson_buffer bb;
	
	bson query;
	bson field;
	bson result;
	
	bson_buffer_init(&bb);
	bson_append_string(&bb, dbi->search, mac);
	bson_from_buffer(&query, &bb);
	
	bson_empty(&field);

	bson_empty(&result);

	printf("Searching %s in schema %s => %s, %s => ?\n", mac, dbi->dns, mac, dbi->ip);

	MONGO_TRY{
		if (mongo_find_one(conn, dbi->base, &query, &field, &result) == 0) {
			return 0;
		}
	}MONGO_CATCH{
		mongo_start(dbdata);
		return 0;
	}

	bson_iterator it;
	bson_iterator_init(&it, result.data);
	
	find_in_array(&it, dbi->dns, mac, dbi->ip, dhcp);
	return 1;
}

static isc_result_t
mongodb_lookup(const char *zone, const char *name, void *dbdata,
	      dns_sdblookup_t *lookup)
{
	dbinfo_t *dbi = (dbinfo_t *) dbdata;
	isc_result_t result;

	UNUSED(zone);
	UNUSED(dbdata);
	
	if (strcmp(name, "@") == 0)
		return (ISC_R_NOTFOUND);
		
	printf("Search prefix : \"%s\", result suffix : \"%s\"\n", dbi->search_prefix, dbi->result_suffix); 
	
	char reference[MONGO_STRING_LENGTH];
	sprintf(reference, "%s%s", dbi->search_prefix, name);
	
	char option_buffer[MONGO_STRING_LENGTH] = "";

	if (find_bind_options(dbdata, reference, option_buffer)) {
		sprintf(option_buffer, "%s%s", option_buffer, dbi->result_suffix);
		printf("DNS entry found for %s : %s\n", name, option_buffer);
		result = dns_sdb_putrr(lookup, dbi->request_type, 86400, option_buffer);
		if (result != ISC_R_SUCCESS)
			return (ISC_R_FAILURE);
	} else {
		return (ISC_R_NOTFOUND);
	}

	return (ISC_R_SUCCESS);
}

static isc_result_t
mongodb_authority(const char *zone, void *dbdata, dns_sdblookup_t *lookup) {
	isc_result_t result;

	UNUSED(zone);
	UNUSED(dbdata);
  
  time_t rawtime;
  struct tm *timeinfo;
  char buffer[11];

  time(&rawtime);
  timeinfo = localtime(&rawtime);

  strftime(buffer, 11, "%Y%m%d01", timeinfo);
  
	result = dns_sdb_putsoa(lookup, "localhost.", "root.localhost.", atoi(buffer)); //  YYYYMMDDXX
	if (result != ISC_R_SUCCESS)
		return (ISC_R_FAILURE);

	result = dns_sdb_putrr(lookup, "ns", 86400, "ns1.localdomain.");
	if (result != ISC_R_SUCCESS)
		return (ISC_R_FAILURE);
	result = dns_sdb_putrr(lookup, "ns", 86400, "ns2.localdomain.");
	if (result != ISC_R_SUCCESS)
		return (ISC_R_FAILURE);

	return (ISC_R_SUCCESS);
}

#define STRDUP_OR_FAIL(target, source)				\
	do {							\
		target = isc_mem_strdup(ns_g_mctx, source);	\
		if (target == NULL) {				\
			result = ISC_R_NOMEMORY;		\
			goto cleanup;				\
		}						\
	} while (0);


static isc_result_t
mongodb_create(const char *zone,
		int argc, char **argv,
		void *driverdata, void **dbdata)
{
    dbinfo_t *dbi;
    isc_result_t result;
    
    UNUSED(zone);
    UNUSED(driverdata);

    if (argc < 7)
			return (ISC_R_FAILURE);

    dbi = isc_mem_get(ns_g_mctx, sizeof(dbinfo_t));
    if (dbi == NULL)
			return (ISC_R_NOMEMORY);

    dbi->host 		= NULL;
    dbi->port    	= NULL;
		dbi->request_type = NULL;
		dbi->base 		= NULL;
    dbi->search   = NULL;
    dbi->dns 			= NULL;
    dbi->ip    		= NULL;
    dbi->search_prefix   = "";
    dbi->result_suffix   = "";
    
    dbi->zone   = zone;
    
    STRDUP_OR_FAIL(dbi->host, argv[0]);
    STRDUP_OR_FAIL(dbi->port, argv[1]);
    STRDUP_OR_FAIL(dbi->request_type, argv[2]);
    STRDUP_OR_FAIL(dbi->base, argv[3]);
    STRDUP_OR_FAIL(dbi->search, argv[4]);
    STRDUP_OR_FAIL(dbi->dns, argv[5]);
    STRDUP_OR_FAIL(dbi->ip, argv[6]);
    
    if (argc > 7) {
    	 STRDUP_OR_FAIL(dbi->search_prefix, argv[7]);
    	 STRDUP_OR_FAIL(dbi->result_suffix, argv[8]);
    }
    	    	 
    *dbdata = dbi;
    
    mongo_start(dbi);
  
    return (ISC_R_SUCCESS);

cleanup:
    mongodb_destroy(zone, driverdata, (void **)&dbi);
    return (result);
}

void
mongodb_destroy(const char *zone, void *driverdata, void **dbdata)
{
    UNUSED(zone);
    UNUSED(driverdata);
		UNUSED(dbdata);
		
	 	mongodb_lock(1);
		item *connection = chercher(connection_list, zone);
		mongodb_lock(-1);
	
		mongo_destroy(connection->conn);
}

static dns_sdbmethods_t mongodb_methods = {
	mongodb_lookup,
	mongodb_authority,
	NULL,	/* allnodes */
	mongodb_create,	/* create */
	mongodb_destroy	/* destroy */
};

isc_result_t
mongodb_init(void) {
	unsigned int flags;
	flags = DNS_SDBFLAG_RELATIVEOWNER | DNS_SDBFLAG_RELATIVERDATA | DNS_SDBFLAG_THREADSAFE;
	
	mongodb_lock(0);
	
	return (dns_sdb_register("mongo", &mongodb_methods, NULL, flags,
				 ns_g_mctx, &mongodb));
}

void
mongodb_clear(void) {
	if (mongodb != NULL)
		dns_sdb_unregister(&mongodb);
}
