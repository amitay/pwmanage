#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <rpc/des_crypt.h>

#include <tdb.h>
#include <talloc.h>

#include "config.h"


struct pw_context {
	char *progname;
	struct tdb_context *tdb;
};

struct pw_header {
	time_t mtime;
};

struct pw_encdata {
	char id[4];
	unsigned int len;
};
	
struct pw_data {
	struct pw_header header;
	struct pw_encdata encdata;
	char start;
};

enum PW_ACTION {
	PW_NONE = 0,
	PW_INIT = 1,
	PW_LIST = 2,
	PW_ADD = 3,
	PW_DEL = 4,
	PW_EDIT = 5,
	PW_SEARCH = 6,
	PW_RENAME = 7,
};


/*
 * Display program usage
 */
void
pw_usage(struct pw_context *ctx)
{
	printf("%s (%s) - Password Manager\n", ctx->progname, PWMANAGE_VERSION);
	printf("Usage:\n");
	printf("   pwmanage init                - Initialize database\n");
	printf("   pwmanage add <key>           - Add new record to database\n");
	printf("   pwmanage del <key>           - Delete a record from database\n");
	printf("   pwmanage edit <key>          - Edit an existing record\n");
	printf("   pwmanage move <key> <newkey> - Rename a key\n");
	printf("   pwmanage list                - List all the keys\n");
	printf("   pwmanage <key>               - Extract the details\n");
	exit(0);
}


/*
 * Free TDB data memory
 */
void
pw_tdb_free(TDB_DATA *data)
{
	if(data->dptr) {
		free(data->dptr);
	}
	data->dsize = 0;
}

/*
 * Debug routine, dump string in hex
 */
void
pw_dump(unsigned char *str, unsigned int len)
{
	int i;

	for(i=0; i<len; i++) {
		printf("%02x ", str[i]);
		if((i+1) % 16 == 0) printf("\n");
	}
	printf("\n");
}

/*
 * Construct the path to $HOME/.pw.tdb
 */
char *
pw_get_filepath(struct pw_context *ctx)
{
	char *filename = ".pw.tdb";
	char *homedir;
	char *path;

	homedir = getenv("HOME");
	if(homedir == NULL) {
		path = strdup(filename);
	} else {
		path = talloc_zero_size(ctx, strlen(homedir) + strlen(filename) + 2);
		path = talloc_asprintf(ctx, "%s/%s", homedir, filename);	
	}
	return path;
}


/*
 * Initialize TDB database
 */
int
pw_init(struct pw_context *ctx)
{
	char *path;

	path = pw_get_filepath(ctx);
	ctx->tdb = tdb_open(path, 0, TDB_CLEAR_IF_FIRST, 
				O_RDWR|O_CREAT|O_EXCL, 0600);
	if(ctx->tdb == NULL) {
		fprintf(stderr, "%s: Error creating database.\n", ctx->progname);
		return -1;
	}
	tdb_close(ctx->tdb);
	ctx->tdb = NULL;

	TALLOC_FREE(path);

	return 0;
}
		

/*
 * Open TDB database and return the handle
 */
int
pw_open(struct pw_context *ctx)
{
	char *path;

	path = pw_get_filepath(ctx);
	ctx->tdb = tdb_open(path, 0, 0, O_RDWR, 0600);
	if(ctx->tdb == NULL) {
		fprintf(stderr, "%s: Error opening database.\n", ctx->progname);
		return -1;
	}

	return 0;
}


/*
 * Callback routine to print each key
 * Invoked from TDB traversal routine
 */
int
pw_print_key(struct tdb_context *tdb, TDB_DATA key, TDB_DATA value, void *pdata)
{
	struct pw_header *header;
	char *keystr;

	header = (struct pw_header *) value.dptr;
	keystr = talloc_strndup(NULL, (char *)key.dptr, key.dsize);

	printf("%-32s : %s", keystr, ctime(&(header->mtime)));

	talloc_free(keystr);

	return 0;
}

/*
 * List all the keys in database
 */
int
pw_list(struct pw_context *ctx)
{
	return tdb_traverse_read(ctx->tdb, pw_print_key, NULL);
}


/*
 * Allow user to edit the secret using /bin/vi or editor defined in 
 * EDITOR environmental variable
 *
 * TODO: Need to check the return value from editor
 */
int
pw_user_edit(struct pw_context *ctx, TDB_DATA *data)
{
	int fd;
	char *tmppath;
	char *editor;
	char *cmd;
	int retval = 0;
	struct stat buf;
	unsigned int n;

	/* create temporary file with secret data */
	tmppath = tmpnam(NULL);
	fd = open(tmppath, O_CREAT|O_TRUNC|O_RDWR, 0600);
	if(fd < 0) {
		fprintf(stderr, "%s: Could not create temporary file.\n", 
			ctx->progname);
		exit(1);
	}
	if(data->dsize > 0) {
		write(fd, data->dptr, data->dsize);
	}
	close(fd);

	/* invoke editor */
	editor = getenv("EDITOR");
	if(editor == NULL) {
		fprintf(stderr, "%s: Variable EDITOR not defined.\n", 
				ctx->progname);
		return -1;
	}
	cmd = talloc_zero_size(ctx, strlen(editor) + strlen(tmppath) + 2);
	cmd = talloc_asprintf(ctx, "%s %s", editor, tmppath);
	retval = system(cmd);
	talloc_free(cmd);

	/* read from temporary file and delete the file */
	fd = open(tmppath, O_RDONLY);
	unlink(tmppath);
	fstat(fd, &buf);
	n = buf.st_size;

	if(data->dsize > 0) {
		talloc_free(data->dptr);
	}
	data->dptr = talloc_zero_size(ctx, n);
	data->dsize = n;
	read(fd, data->dptr, data->dsize);
	close(fd);

	return retval;
}


/*
 * Read password from user
 *
 * confirm = 1, Confirm the password from user
 * confirm = 0, accept the first password as is
 */
char *
pw_getpass(char confirm)
{
	char *pass, *skey;
	int done = 0, tries = 0;

	while(!done && tries < 3) {
		pass = getpass("Password: ");
		skey = talloc_strdup(NULL, pass);
		if(confirm) {
			pass = getpass("Confirm: ");
			if(strncmp(skey, pass, strlen(skey)) == 0) {
				done = 1;
			} else {
				talloc_free(skey);
				fprintf(stderr, "Passwords do not match. Try again\n");
				tries++;
			}
		} else {
			done = 1;
		}
	}

	if(! done) {
		fprintf(stderr, "Exiting\n");
		exit(1);
	}

	return skey;
}


/*
 * Encryption / Decryption of using CBC
 * 
 * Maximum password length = 16
 * First (up to) 8 characters are copied as key 
 * Remaining (up to) 8 characters are copied as mode
 * If password is smaller than 8 chars, is padded with numbers
 */

void
pw_crypt(char *skey, char *secret, unsigned int len, char encrypt)
{
	char key[9] = "01234567", mode[9] = "12345678";
	int n;

	n = strlen(skey);
	if(n > 16) {
		n = 16;
	}
	if(n <= 8) {
		memcpy((void *)key, (void *)skey, n);
	} else {
		memcpy((void *)key, (void *)skey, 8);
		memcpy((void *)mode, (void *)&skey[8], n-8);
	}
	des_setparity(key);

	if(encrypt) {
		cbc_crypt(key, secret, len, DES_ENCRYPT | DES_SW, mode);
	} else {
		cbc_crypt(key, secret, len, DES_DECRYPT | DES_SW, mode);
	}
}


/*
 * Encode secret data with meta-data
 *
 *    ecrypted data = 3 bytes of key + null + length + secret data
 *    encoded data = timestamp + encrypted data
 *     (timestamp is not encrypted)
 */
int
pw_encode(TDB_DATA key, TDB_DATA secret, TDB_DATA *enc_secret, char *pass)
{
	char *skey;
	TDB_DATA data;
	unsigned int len;
	struct pw_encdata *encdata;
	struct pw_header *header;

	len = sizeof(struct pw_encdata) + secret.dsize;
	if((len & (unsigned int)0x07) > 0) {
		len = ((len >> 3) + 1) << 3;
	}

	data.dsize = len;
	data.dptr = talloc_zero_size(NULL, data.dsize);

	encdata = (struct pw_encdata *)data.dptr;

	/* first 3 letters of key */
	strncpy(encdata->id, (char *)key.dptr, 3);
	encdata->id[3] = '\0';

	/* size of secret */
	encdata->len = secret.dsize;

	/* actual secret data */
	memcpy((void *)(data.dptr + sizeof(struct pw_encdata)), 
		secret.dptr, secret.dsize);	

	if(pass == NULL) {
		skey = pw_getpass(1);
	} else {
		skey = pass;
	}
	pw_crypt(skey, (char *)data.dptr, data.dsize, 1);
	if(pass == NULL) {
		TALLOC_FREE(skey);
	} else {
		skey = NULL;
	}

	enc_secret->dsize = sizeof(struct pw_header) + data.dsize;
	enc_secret->dptr = talloc_zero_size(NULL, enc_secret->dsize);

	header = (struct pw_header *)enc_secret->dptr;
	header->mtime = time(NULL);

	memcpy((void *)(enc_secret->dptr + sizeof(struct pw_header)), 
		data.dptr, data.dsize);

	TALLOC_FREE(data.dptr);
	return 0;
}


/*
 * Decode encoded data to secret data
 *
 * Decrypt the encrypted data and verify that the first 3 bytes of key
 * match the id stored in encrypted data. If they do not match, wrong
 * password used to decrypt the data.
 */
int
pw_decode(TDB_DATA key, TDB_DATA enc_secret, TDB_DATA *secret, char **pass)
{
	char *skey;
	TDB_DATA data;
	struct pw_encdata *encdata;
	int done = 0, tries = 0;

	data.dsize = enc_secret.dsize - sizeof(struct pw_header);
	data.dptr = talloc_zero_size(NULL, data.dsize);

	while(!done && tries < 3) {
		memcpy((void *)data.dptr, 
			(void *)(enc_secret.dptr + sizeof(struct pw_header)), 
			data.dsize);

		skey = pw_getpass(0);
		pw_crypt(skey, (char *)data.dptr, data.dsize, 0);

		encdata = (struct pw_encdata *)data.dptr;
		if(strncmp((char *)key.dptr, encdata->id, 3) == 0) {
			secret->dsize = encdata->len;
			secret->dptr = talloc_zero_size(NULL, secret->dsize);

			memcpy((void *)secret->dptr, 
				(void *)(data.dptr + sizeof(struct pw_encdata)),
				secret->dsize);

			if(pass != NULL) {
				*pass = talloc_strdup(NULL, skey);
			}
			done = 1;
		} else {
			fprintf(stderr, "Invalid password, try again.\n");
			tries++;
		}
		TALLOC_FREE(skey);
	}

	TALLOC_FREE(data.dptr);

	if(!done) {
		fprintf(stderr, "Too many failures.\n");
		secret->dsize = 0;
		return -1;
	}

	return 0;
}

/*
 * Add a new record in database
 */
int
pw_add(struct pw_context *ctx, TDB_DATA key)
{
	TDB_DATA secret, enc_secret;

	secret.dptr = 0;
	secret.dsize = 0;
	if(pw_user_edit(ctx, &secret) < 0) {
		return -1;
	}

	if(pw_encode(key, secret, &enc_secret, NULL) < 0) {
		return -1;
	}

	if(tdb_store(ctx->tdb, key, enc_secret, TDB_INSERT) < 0) {
		fprintf(stderr, "%s: %s\n", ctx->progname, 
				tdb_errorstr(ctx->tdb));
		return -1;
	}

	return 0;
}


/*
 * Delete a record from database
 */
int
pw_del(struct pw_context *ctx, TDB_DATA key)
{
	int response;

	printf("Deleting %s, confirm (y/N): ", key.dptr);
	response = getchar();
	if(response == (int)'y' || response == (int)'Y') {
		if(tdb_delete(ctx->tdb, key) < 0) {
			fprintf(stderr, "%s: %s\n", ctx->progname, 
				tdb_errorstr(ctx->tdb));
			return -1;
		}
	}
	return 0;
}


/*
 * Edit an existing record from database
 */
int
pw_edit(struct pw_context *ctx, TDB_DATA key)
{
	TDB_DATA enc_secret, secret;
	char *skey;

	enc_secret = tdb_fetch(ctx->tdb, key);
	if(pw_decode(key, enc_secret, &secret, &skey) < 0) {
		return -1;
	}
	pw_tdb_free(&enc_secret);
	

	if(pw_user_edit(ctx, &secret) < 0) {
		return -1;
	}

	if(pw_encode(key, secret, &enc_secret, skey) < 0) {
		return -1;
	}

	if(tdb_store(ctx->tdb, key, enc_secret, TDB_REPLACE) < 0) {
		fprintf(stderr, "%s: %s\n", ctx->progname, 
				tdb_errorstr(ctx->tdb));
		return -1;
	}
	return 0;
}


/*
 * Print the secret data corresponding to given key
 *
 * Assumption: The secret data is printable and not binary BLOB
 */
int
pw_search(struct pw_context *ctx, TDB_DATA key)
{
	TDB_DATA enc_secret, secret;
	char *str;

	enc_secret = tdb_fetch(ctx->tdb, key);
	if(pw_decode(key, enc_secret, &secret, NULL) < 0) {
		return -1;
	}
	pw_tdb_free(&enc_secret);

	str = talloc_strndup(NULL, (char *)secret.dptr, secret.dsize);

	printf("%s\n", str);

	talloc_free(str);
	talloc_free(secret.dptr);

	return 0;
}


/*
 * Rename the key in database 
 */
int
pw_rename(struct pw_context *ctx, TDB_DATA key, TDB_DATA key2)
{
	TDB_DATA enc_secret, secret;
	char *skey;

	if(tdb_transaction_start(ctx->tdb) < 0) {
		return -1;
	}

	enc_secret = tdb_fetch(ctx->tdb, key);
	if(pw_decode(key, enc_secret, &secret, &skey)) {
		return -1;
	}
	pw_tdb_free(&enc_secret);
	if(pw_encode(key2, secret, &enc_secret, skey)) {
		return -1;
	}

	if(tdb_store(ctx->tdb, key2, enc_secret, TDB_INSERT) < 0) {
		fprintf(stderr, "%s: %s\n", ctx->progname, 
				tdb_errorstr(ctx->tdb));
		tdb_transaction_cancel(ctx->tdb);
		return -1;
	}

	if(tdb_delete(ctx->tdb, key) < 0) {
		fprintf(stderr, "%s: %s\n", ctx->progname, 
				tdb_errorstr(ctx->tdb));
		tdb_transaction_cancel(ctx->tdb);
		return -1;
	}
		
	if(tdb_transaction_commit(ctx->tdb) < 0) {
		fprintf(stderr, "%s: %s\n", ctx->progname, 
				tdb_errorstr(ctx->tdb));
		return -1;
	}

	return 0;
}


int
main(int argc, char *argv[])
{
	enum PW_ACTION action;
	int need_arg = 0;
	char *pattern = NULL, *pattern2 = NULL;
	int retval = 0;
	TDB_DATA key, key2;
	int key_exists, key2_exists;
	struct pw_context *ctx;
	void *tctx;

	/* Talloc context */
	tctx = talloc_init("pwmanage");
	ctx = (struct pw_context *)talloc(tctx, struct pw_context);

	ctx->tdb = NULL;
	ctx->progname = talloc_strdup(ctx, argv[0]);

	if(argc < 2) {
		pw_usage(ctx);
	}

	if(strcmp(argv[1], "init") == 0) {
		action = PW_INIT;
	} else if(strcmp(argv[1], "list") == 0) {
		action = PW_LIST;
	} else if(strcmp(argv[1], "add") == 0) {
		action = PW_ADD;
		need_arg = 1;
	} else if(strcmp(argv[1], "del") == 0) {
		action = PW_DEL;
		need_arg = 1;
	} else if(strcmp(argv[1], "edit") == 0) {
		action = PW_EDIT;
		need_arg = 1;
	} else if(strcmp(argv[1], "move") == 0) {
		action = PW_RENAME;
		need_arg = 2;
	} else {
		action = PW_SEARCH;
		pattern = argv[1];
	}

	if(need_arg > 0 && argc != 2 + need_arg) {
		pw_usage(ctx);
	}

	if(argc >= 3) {
		pattern = argv[2];
		if(strlen(pattern) < 3) {
			fprintf(stderr, "%s: Key (%s) too small\n", 
				ctx->progname, pattern);
			retval = 1;
			goto end;
		}

	}
	if(argc >= 4) {
		pattern2 = argv[3];
		if(strlen(pattern2) < 3) {
			fprintf(stderr, "%s: Key (%s) too small\n", 
				ctx->progname, pattern2);
			retval = 1;
			goto end;
		}
	}

	if(action == PW_INIT) {
		retval = pw_init(ctx);
		goto end;
	}

	if(pw_open(ctx) < 0) {
		retval = 1;
		goto end;
	}

	if(action == PW_LIST) {
		retval = pw_list(ctx);
		goto end;
	}

	key.dptr = (unsigned char *)talloc_strdup(ctx, pattern);
	key.dsize = strlen(pattern);

	key_exists = tdb_exists(ctx->tdb, key);

	if(pattern2 != NULL) {
		key2.dptr = (unsigned char *)talloc_strdup(ctx, pattern2);
		key2.dsize = strlen(pattern2);
	
		key2_exists = tdb_exists(ctx->tdb, key2);
	}

	if(action == PW_ADD) {
		if(key_exists) {
			fprintf(stderr, "%s: Key (%s) already exists.\n", 
				ctx->progname, pattern);
			retval = 1;
		} else {
			retval = pw_add(ctx, key);
		}
		goto end;
	}

	if(action == PW_EDIT || action == PW_DEL || action == PW_SEARCH) {
		if(! key_exists) {
			fprintf(stderr, "%s: Key (%s) does not exist.\n",
				ctx->progname, pattern);
			retval = 1;
		} else {
			if(action == PW_EDIT) {
				retval = pw_edit(ctx, key);
			} else if(action == PW_DEL) {
				retval = pw_del(ctx, key);
			} else {
				retval = pw_search(ctx, key);
			}
		}
		goto end;
	}

	if(action == PW_RENAME) {
		if(! key_exists) {
			fprintf(stderr, "%s: Key (%s) does not exist.\n",
				ctx->progname, pattern);
			retval = 1;
		} else if(key2_exists) {
			fprintf(stderr, "%s: Key (%s) already exists.\n",
				ctx->progname, pattern2);
			retval = 1;
		} else {
			retval = pw_rename(ctx, key, key2);
		}
	}

end:
	if(ctx->tdb) {
		tdb_close(ctx->tdb);
	}

	// talloc_report_full(tctx, stdout);
	talloc_free(tctx);

	exit(retval);
}
