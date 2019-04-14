#include "libssh/libssh.h"
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <mntent.h>

#define MAX_XFER_BUF_SIZE 32768

/* Copied from the tutorial */
int verify_knownhost(ssh_session session) {
	int state, rc;
	size_t hlen;
	unsigned char *hash = NULL;
	char *hexa;
	char buf[10];
	ssh_key srv_pubkey;

	state = ssh_is_server_known(session);

	/* Added this bit because ssh_get_pubkey_hash was deprecated */
	rc = ssh_get_server_publickey(session, &srv_pubkey);
	if (rc < 0) {
		return -1;
	}
	rc = ssh_get_publickey_hash(srv_pubkey,
		SSH_PUBLICKEY_HASH_SHA1,
		&hash,
		&hlen);
	ssh_key_free(srv_pubkey);
	if (rc < 0) {
		return -1;
	}


	if (hlen < 0)
		return -1;
	switch (state) {
	case SSH_SERVER_KNOWN_OK:
		break; /* ok */
	case SSH_SERVER_KNOWN_CHANGED:
		fprintf(stderr, "Host key for server changed: it is now:\n");
		ssh_print_hexa("Public key hash", hash, hlen);
		fprintf(stderr, "For security reasons, connection will be stopped\n");
		free(hash);
		return -1;
	case SSH_SERVER_FOUND_OTHER:
		fprintf(stderr, "The host key for this server was not found but an other"
			"type of key exists.\n");
		fprintf(stderr, "An attacker might change the default server key to"
			"confuse your client into thinking the key does not exist\n");
		free(hash);
		return -1;
	case SSH_SERVER_FILE_NOT_FOUND:
		fprintf(stderr, "Could not find known host file.\n");
		fprintf(stderr, "If you accept the host key here, the file will be"
			"automatically created.\n");
	/* fallback to SSH_SERVER_NOT_KNOWN behavior */
	case SSH_SERVER_NOT_KNOWN:
		hexa = ssh_get_hexa(hash, hlen);
		fprintf(stderr, "The server is unknown. Do you trust the host key?\n");
		fprintf(stderr, "Public key hash: %s\n", hexa);
		free(hexa);
		if (fgets(buf, sizeof(buf), stdin) == NULL) {
			free(hash);
			return -1;
		}
		if (strncasecmp(buf, "yes", 3) != 0) {
			free(hash);
			return -1;
		}
		if (ssh_write_knownhost(session) < 0) {
			fprintf(stderr, "Error %s\n", strerror(errno));
			free(hash);
			return -1;
		}
		break;
	case SSH_SERVER_ERROR:
		fprintf(stderr, "Error %s", ssh_get_error(session));
		free(hash);
		return -1;
	}
	free(hash);
	return 0;
}

/* Copied from the tutorial but modified to write larger files */
int scp_receive(ssh_session session, ssh_scp scp) {
	int rc;
	int size, mode, nwritten;
	char *filename, *buffer;

	/* Get remote file attributes */
	size = ssh_scp_request_get_size(scp);
	filename = strdup(ssh_scp_request_get_filename(scp));
	mode = ssh_scp_request_get_permissions(scp);
	//printf("Receiving file %s, size %d, permissions 0%o\n", filename, size, mode);

	int fd = open(filename, O_CREAT | O_WRONLY | O_EXCL, mode);
	free(filename);
	if (fd < 0) {
		if (errno == EEXIST) {
			/* the file already existed */
			//puts("The file already exists");
			return ssh_scp_deny_request(scp, "Already Exists");
		}
		fprintf(stderr, "Can't open file for writing: %s\n", strerror(errno));
		return SSH_ERROR;
	}

	ssh_scp_accept_request(scp);

	/* Allocate buffer for writing */
	buffer = malloc(MAX_XFER_BUF_SIZE);
	if (buffer == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		return SSH_ERROR;
	}

	/* Receive file in MAX_XFER_BUF_SIZE chunks and write them every time */
	while (size > 0) {
		rc = ssh_scp_read(scp, buffer, MAX_XFER_BUF_SIZE);
		if (rc == SSH_ERROR) {
			fprintf(stderr, "Error receiving file data: %s\n", ssh_get_error(session));
			free(buffer);
			return rc;
		}
		nwritten = write(fd, buffer, rc);
		if (nwritten != rc) {
			fprintf(stderr, "Error writing: %s\n", strerror(errno));
			free(buffer);
			return SSH_ERROR;
		}
		size -= nwritten;
	}
	// TODO: Add some check to the file

	/* Free buffer and close file */
	free(buffer);
	close(fd);

	return SSH_OK;
}

/* Copied from the tutorial */
int scp_read(ssh_session session, const char *SRC_DIR) {
	ssh_scp scp;
	char *filename;
	int rc, mode;

	/* Set SCP to read and provide file name */
	scp = ssh_scp_new(session, SSH_SCP_READ | SSH_SCP_RECURSIVE, SRC_DIR);
	if (scp == NULL) {
		fprintf(stderr, "Error allocating scp session: %s\n",
			ssh_get_error(session));
		return SSH_ERROR;
	}

	rc = ssh_scp_init(scp);
	if (rc != SSH_OK) {
		fprintf(stderr, "Error initializing scp session: %s\n",
			ssh_get_error(session));
		ssh_scp_free(scp);
		return rc;
	}

	/* Start reading */
	do {
		rc = ssh_scp_pull_request(scp);
		switch (rc) {
		case SSH_SCP_REQUEST_NEWFILE:
			if (scp_receive(session, scp) != SSH_OK) {
				fprintf(stderr, "Error: %s\n", ssh_get_error(session));
			}
			break;
		case SSH_ERROR:
			fprintf(stderr, "Error: %s\n", ssh_get_error(session));
			break;
		case SSH_SCP_REQUEST_WARNING:
			fprintf(stderr, "Warning: %s\n", ssh_scp_request_get_warning(scp));
			break;
		case SSH_SCP_REQUEST_NEWDIR:
			filename = strdup(ssh_scp_request_get_filename(scp));
			mode = ssh_scp_request_get_permissions(scp);
			//printf("downloading directory %s, perms 0%o\n", filename, mode);
			ssh_scp_accept_request(scp);
			if (mkdir(filename, mode) != 0 && errno != EEXIST) {
				fprintf(stderr, "Cannot create dir: %s\n", strerror(errno));
				rc = SSH_ERROR;
			}
			if (chdir(filename)) {
				fprintf(stderr, "Could not change directory: %s\n", strerror(errno));
				rc = SSH_ERROR;
			}
			free(filename);
			break;
		case SSH_SCP_REQUEST_ENDDIR:
			//printf("End of directory\n");
			chdir("..");
			/* I'm a one step closer to the edge, I'm about to... */ break;
		}
		sleep(1);
	} while (rc != SSH_SCP_REQUEST_EOF && rc != SSH_ERROR);

	/* Close SCP channel */
	ssh_scp_close(scp);
	ssh_scp_free(scp);

	return rc;
}

/* Check if the path is a folder and exists */
int is_folder(char *folder) {

	struct stat sb;

	if (stat(folder, &sb) == 0 && S_ISDIR(sb.st_mode)) {
		/* The path is a folder */
		return 1;
	}
	else {
		/* It's not a folder */
		return 0;
	}

}

int main(int argc, char *argv[]) {

	/* Check if the only argument, the source folder, is specified */
	if (argc != 5) {
		//puts("Usage: ./MovieMover SRC_DIR HOST USER");
		exit(EXIT_FAILURE);
	}
	char *SRC_DIR = argv[1], *DEST_DIR=argv[2], *HOST = argv[3], *USER = argv[4];

	// TODO: prevent system shutdown while running

	if (!(is_folder(SRC_DIR))) {
		//puts("The path is not a directory (either is a file or it is non existant");
		exit(EXIT_FAILURE);
	}

	/* Change directory */
	if (chdir(DEST_DIR)) {
		fprintf(stderr, "Could not change directory: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Initialize new SSH session */
	ssh_session my_ssh_session = ssh_new();
	if (my_ssh_session == NULL) {
		//puts("Could not open SSH session");
		exit(EXIT_FAILURE);
	}

	/* Set SSH options */
	int verbosity = SSH_LOG_NOLOG;
	int port = 22;
	ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, HOST);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, USER);

	/* Establish the connection */
	int rc = ssh_connect(my_ssh_session);
	if (rc != SSH_OK) {
		fprintf(stderr, "Error connecting to localhost: %s\n", ssh_get_error(my_ssh_session));
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		exit(EXIT_FAILURE);
	}


	/* Verify the server identity */
	if (verify_knownhost(my_ssh_session) < 0) {
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		exit(EXIT_FAILURE);
	}

	/* Authenticate to the server */
	rc = ssh_userauth_publickey_auto(my_ssh_session, USER, NULL);	// Keys should be in ~/.ssh/
	if (rc != SSH_AUTH_SUCCESS) {
		fprintf(stderr, "Error authenticating with public key: %s\n",
			ssh_get_error(my_ssh_session));
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		exit(EXIT_FAILURE);
	}

	/* Start the SCP channel */
	// TODO: Remove copied files
	scp_read(my_ssh_session, SRC_DIR);

	/* Disconnect and close */
	ssh_disconnect(my_ssh_session);
	ssh_free(my_ssh_session);
	return 0;
}