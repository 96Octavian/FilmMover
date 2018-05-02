#include "libssh/libssh.h"
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/unistd.h>

#define MAX_XFER_BUF_SIZE 32768

/* Copied from the tutorial */
int verify_knownhost(ssh_session session) {
	int state, hlen, rc;
	unsigned char *hash = NULL;
	char *hexa;
	char buf[10];
	ssh_key srv_pubkey;

	state = ssh_is_server_known(session);

	/* Added this bit because ssh_get_pubkey_hash was deprecated */
	rc = ssh_get_publickey(session, &srv_pubkey);
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
	switch (state)
	{
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
		if (fgets(buf, sizeof(buf), stdin) == NULL)
		{
			free(hash);
			return -1;
		}
		if (strncasecmp(buf, "yes", 3) != 0)
		{
			free(hash);
			return -1;
		}
		if (ssh_write_knownhost(session) < 0)
		{
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

int scp_receive(ssh_session session, ssh_scp scp) {
	int rc;
	int size, mode, nwritten;
	char *filename, *buffer;

	/* Pull the pending request from remote host */
	rc = ssh_scp_pull_request(scp);
	if (rc != SSH_SCP_REQUEST_NEWFILE) {
		fprintf(stderr, "Error receiving information about file: %s\n",
			ssh_get_error(session));
		return SSH_ERROR;
	}

	/* Get remote file attributes */
	size = ssh_scp_request_get_size(scp);
	filename = strdup(ssh_scp_request_get_filename(scp));
	mode = ssh_scp_request_get_permissions(scp);
	printf("Receiving file %s, size %d, permissions 0%o\n", filename, size, mode);

	/* Allocate buffer for writing */
	buffer = malloc(MAX_XFER_BUF_SIZE);
	if (buffer == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		return SSH_ERROR;
	}

	ssh_scp_accept_request(scp);

	int fd = open(filename, O_CREAT | O_WRONLY, mode);
	free(filename);
	if (fd < 0) {
		fprintf(stderr, "Can't open file for writing: %s\n",
			strerror(errno));
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

	/* If there is no other pending data to be downloaded, we're ok */
	rc = ssh_scp_pull_request(scp);
	if (rc != SSH_SCP_REQUEST_EOF) {
		fprintf(stderr, "Unexpected request: %s\n",
			ssh_get_error(session));
		return SSH_ERROR;
	}
	return SSH_OK;
}

int scp_read(ssh_session session) {
	ssh_scp scp;
	int rc;

	/* Set SCP to read and provide file name */
	scp = ssh_scp_new(session, SSH_SCP_READ, "downloads/FilmMover/test/file.txt");
	if (scp == NULL)
	{
		fprintf(stderr, "Error allocating scp session: %s\n",
			ssh_get_error(session));
		return SSH_ERROR;
	}

	rc = ssh_scp_init(scp);
	if (rc != SSH_OK)
	{
		fprintf(stderr, "Error initializing scp session: %s\n",
			ssh_get_error(session));
		ssh_scp_free(scp);
		return rc;
	}

	/* Start reading */
	if (scp_receive(session, scp) != SSH_OK) {
		printf("Error: %s\n", ssh_get_error(session));
	}

	/* Close SCP channel */
	ssh_scp_close(scp);
	ssh_scp_free(scp);
	return SSH_OK;
}

int main() {
	/* Initialize new SSH session */
	ssh_session my_ssh_session = ssh_new();
	if (my_ssh_session == NULL) {
		puts("Could not open SSH session");
		exit(-1);
	}

	/* Set SSH options */
	int verbosity = SSH_LOG_PROTOCOL;
	int port = 22;
	ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "pepsipi");
	ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, "octavian");

	/* Establish the connection */
	int rc = ssh_connect(my_ssh_session);
	if (rc != SSH_OK)
	{
		fprintf(stderr, "Error connecting to localhost: %s\n",
			ssh_get_error(my_ssh_session));
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		exit(-1);
	}

	/* Verify the server identity */
	if (verify_knownhost(my_ssh_session) < 0)
	{
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		exit(-1);
	}

	/* Authenticate to the server */
	rc = ssh_userauth_publickey_auto(my_ssh_session, "octavian", NULL);	// Keys should be in ~/.ssh/
	if (rc != SSH_AUTH_SUCCESS)
	{
		fprintf(stderr, "Error authenticating with public key: %s\n",
			ssh_get_error(my_ssh_session));
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		exit(-1);
	}

	/* Start the SCP channel */
	// TODO: Download entire folders and then remove copied files
	scp_read(my_ssh_session);

	/* Disconnect and close */
	ssh_disconnect(my_ssh_session);
	ssh_free(my_ssh_session);
}