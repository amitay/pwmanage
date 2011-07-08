#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <rpc/des_crypt.h>

#include <tdb.h>

#include "config.h"

static char *g__progname = NULL;
static char *g__filename = ".pw.tdb";

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
	PW_SEARCH = 6
};


void
pw_usage(void)
{
	printf("%s (%s) - Password Manager\n", g__progname, PWMANAGE_VERSION);
	printf("Usage:\n");
	printf("   pwmanage init        - Initialize database\n");
	printf("   pwmanage add <key>   - Add a key to database\n");
	printf("   pwmanage del <key>   - Delete key from database\n");
	printf("   pwmanage edit <key>  - Edit existing key from database\n");
	printf("   pwmanage edit <key>  - Edit existing key from database\n");
	printf("   pwmanage list        - List all the keys\n");
	printf("   pwmanage <key>       - Extract the details\n");
	exit(0);
}


char *
pw_get_filepath(void)
{
	char *homedir;
	char *path;

	homedir = getenv("HOME");
	if(homedir == NULL) {
		path = strdup(g__filename);
	} else {
		path = (char *)malloc(strlen(homedir) + strlen(g__filename) + 2);
		sprintf(path, "%s/%s", homedir, g__filename);	
	}
	return path;
}


int
pw_init(void)
{
	char *path;
	struct tdb_context *tdb;

	path = pw_get_filepath();
	tdb = tdb_open(path, 0, TDB_CLEAR_IF_FIRST, O_RDWR|O_CREAT|O_EXCL, 0600);
	if(tdb == NULL) {
		fprintf(stderr, "%s: Error creating database.\n", g__progname);
		return -1;
	}
	free(path);
	tdb_close(tdb);

	return 0;
}
		

struct tdb_context *
pw_open(void)
{
	char *path;
	struct tdb_context *tdb;

	path = pw_get_filepath();
	tdb = tdb_open(path, 0, 0, O_RDWR, 0600);
	if(tdb == NULL) {
		fprintf(stderr, "%s: Error opening database.\n", g__progname);
	}

	return tdb;
}


int
pw_print_key(struct tdb_context *tdb, TDB_DATA key, TDB_DATA value, void *pdata)
{
	char *keystr;
	struct pw_header *header;

	header = (struct pw_header *) value.dptr;
	keystr = strndup((char *)key.dptr, key.dsize);
	printf("%-32s : %s", keystr, ctime(&(header->mtime)));
	free(keystr);
	return 0;
}


int
pw_list(struct tdb_context *tdb)
{
	return tdb_traverse_read(tdb, pw_print_key, NULL);
}


void
pw_user_edit(TDB_DATA *data)
{
	int fd;
	char *tmppath;
	char *editor;
	char *cmd;
	int retval;
	struct stat buf;
	unsigned int n;

	tmppath = tmpnam(NULL);
	fd = open(tmppath, O_CREAT|O_TRUNC|O_RDWR, 0600);
	if(fd < 0) {
		fprintf(stderr, "%s: Could not create temporary file.\n", 
			g__progname);
		exit(1);
	}
	if(data->dsize > 0) {
		write(fd, data->dptr, data->dsize);
	}
	close(fd);

	editor = getenv("EDITOR");
	if(editor == NULL) {
		editor = strdup("/bin/vi");
	}
	cmd = (char *)malloc(strlen(editor) + strlen(tmppath) + 2);
	sprintf(cmd, "%s %s", editor, tmppath);
	retval = system(cmd);

	fd = open(tmppath, O_RDONLY);
	unlink(tmppath);
	fstat(fd, &buf);
	n = buf.st_size;

	if(data->dsize > 0) {
		free(data->dptr);
	}
	data->dptr = (unsigned char *)calloc(1, n);
	data->dsize = n;
	read(fd, data->dptr, data->dsize);
	close(fd);
}


char *
pw_getpass(char confirm)
{
	char *pass, *skey;
	int done = 0, tries = 0;

	while(!done && tries < 3) {
		pass = getpass("Password: ");
		skey = strdup(pass);
		if(confirm) {
			pass = getpass("Confirm: ");
			if(strncmp(skey, pass, strlen(skey)) == 0) {
				done = 1;
			} else {
				free(skey);
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


TDB_DATA
pw_encode(TDB_DATA key, TDB_DATA secret, char *pass)
{
	char *skey;
	TDB_DATA data, enc_secret;
	unsigned int len;
	struct pw_encdata *encdata;
	struct pw_header *header;

	len = sizeof(struct pw_encdata) + secret.dsize;
	if((len & (unsigned int)0x07) > 0) {
		len = ((len >> 3) + 1) << 3;
	}

	data.dsize = len;
	data.dptr = (unsigned char *)calloc(1, data.dsize);

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
	free(skey);

	enc_secret.dsize = sizeof(struct pw_header) + data.dsize;
	enc_secret.dptr = (unsigned char *)calloc(1, enc_secret.dsize);

	header = (struct pw_header *)enc_secret.dptr;
	header->mtime = time(NULL);

	memcpy((void *)(enc_secret.dptr + sizeof(struct pw_header)), 
		data.dptr, data.dsize);

	free(data.dptr);
	return enc_secret;
}


TDB_DATA
pw_decode(TDB_DATA key, TDB_DATA enc_secret, char **pass)
{
	char *skey;
	TDB_DATA data, secret;
	struct pw_encdata *encdata;
	int done = 0, tries = 0;

	data.dsize = enc_secret.dsize - sizeof(struct pw_header);
	data.dptr = (unsigned char *)calloc(1, data.dsize);

	while(!done && tries < 3) {
		memcpy((void *)data.dptr, 
			(void *)(enc_secret.dptr + sizeof(struct pw_header)), 
			data.dsize);

		skey = pw_getpass(0);
		pw_crypt(skey, (char *)data.dptr, data.dsize, 0);

		encdata = (struct pw_encdata *)data.dptr;
		if(strncmp((char *)key.dptr, encdata->id, 3) == 0) {
			secret.dsize = encdata->len;
			secret.dptr = (unsigned char *)calloc(1, secret.dsize);

			memcpy((void *)secret.dptr, 
				(void *)(data.dptr + sizeof(struct pw_encdata)),
				secret.dsize);

			if(pass != NULL) {
				*pass = strdup(skey);
			}
			done = 1;
		} else {
			fprintf(stderr, "Invalid password, try again.\n");
			tries++;
		}
		free(skey);
	}

	free(data.dptr);

	if(!done) {
		fprintf(stderr, "Too many failures.\n");
		secret.dsize = 0;
	}

	return secret;
}


int
pw_add(struct tdb_context *tdb, TDB_DATA key)
{
	TDB_DATA secret, enc_secret;

	secret.dptr = 0;
	secret.dsize = 0;
	pw_user_edit(&secret);

	enc_secret = pw_encode(key, secret, NULL);

	if(tdb_store(tdb, key, enc_secret, TDB_INSERT) < 0) {
		fprintf(stderr, "%s: %s\n", g__progname, tdb_errorstr(tdb));
		return -1;
	}

	return 0;
}


int
pw_del(struct tdb_context *tdb, TDB_DATA key)
{
	int response;

	printf("Deleting %s, confirm (y/N): ", key.dptr);
	response = getchar();
	if(response == (int)'y' || response == (int)'Y') {
		if(tdb_delete(tdb, key) < 0) {
			fprintf(stderr, "%s: %s\n", g__progname, tdb_errorstr(tdb));
			return -1;
		}
	}
	return 0;
}


int
pw_edit(struct tdb_context *tdb, TDB_DATA key)
{
	TDB_DATA enc_secret, secret;
	char *skey;

	enc_secret = tdb_fetch(tdb, key);
	secret = pw_decode(key, enc_secret, &skey);
	if(secret.dsize == 0) {
		return -1;
	}

	pw_user_edit(&secret);

	enc_secret = pw_encode(key, enc_secret, skey);

	if(tdb_store(tdb, key, enc_secret, TDB_REPLACE) < 0) {
		fprintf(stderr, "%s: %s\n", g__progname, tdb_errorstr(tdb));
		return -1;
	}
	return 0;
}


int
pw_search(struct tdb_context *tdb, TDB_DATA key)
{
	TDB_DATA enc_secret, secret;

	enc_secret = tdb_fetch(tdb, key);
	secret = pw_decode(key, enc_secret, NULL);
	if(secret.dsize == 0) {
		return -1;
	}

	printf("%s\n", secret.dptr);
	return 0;
}


int
main(int argc, char *argv[])
{
	enum PW_ACTION action;
	int need_arg = 0;
	char *pattern = NULL;
	int retval = 0;
	struct tdb_context *tdb = NULL;
	TDB_DATA key;
	int key_exists;

	g__progname = argv[0];

	if(argc < 2) {
		pw_usage();
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
	} else {
		action = PW_SEARCH;
		pattern = argv[1];
	}

	if(need_arg == 1) {
		if(argc != 3) {
			pw_usage();
		} else {
			pattern = argv[2];
		}
	}

	if(action == PW_INIT) {
		retval = pw_init();
		goto end;
	}

	tdb = pw_open();
	if(tdb == NULL) {
		retval = -1;
		goto end;
	}

	if(action == PW_LIST) {
		retval = pw_list(tdb);
		goto end;
	}

	key.dptr = (unsigned char *)pattern;
	key.dsize = strlen(pattern);

	key_exists = tdb_exists(tdb, key);

	if(action == PW_ADD) {
		if(key_exists) {
			fprintf(stderr, "%s: Key (%s) already exists.\n", 
				g__progname, pattern);
			retval = 1;
		} else {
			retval = pw_add(tdb, key);
		}
		goto end;
	}

	if(action == PW_EDIT || action == PW_DEL || action == PW_SEARCH) {
		if(! key_exists) {
			fprintf(stderr, "%s: Key (%s) does not exist.\n",
				g__progname, pattern);
			retval = 1;
		} else {
			if(action == PW_EDIT) {
				retval = pw_edit(tdb, key);
			} else if(action == PW_DEL) {
				retval = pw_del(tdb, key);
			} else {
				retval = pw_search(tdb, key);
			}
		}
		goto end;
	}

end:

	if(tdb) {
		tdb_close(tdb);
	}
	exit(retval);
}
