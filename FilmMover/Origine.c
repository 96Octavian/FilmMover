#include "libssh/libssh.h"
#include <stdlib.h>
#include "useful.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>

int verify_knownhost(ssh_session session) {
	int state, hlen;
	unsigned char *hash = NULL;
	char *hexa;
	char buf[10];
	state = ssh_is_server_known(session);
	hlen = ssh_get_pubkey_hash(session, &hash);
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
	int size, mode;
	char *filename, *buffer;
	rc = ssh_scp_pull_request(scp);
	if (rc != SSH_SCP_REQUEST_NEWFILE)
	{
		fprintf(stderr, "Error receiving information about file: %s\n",
			ssh_get_error(session));
		return SSH_ERROR;
	}
	size = ssh_scp_request_get_size(scp);
	filename = strdup(ssh_scp_request_get_filename(scp));
	mode = ssh_scp_request_get_permissions(scp);
	printf("Receiving file %s, size %d, permisssions 0%o\n",
		filename, size, mode);
	free(filename);
	buffer = malloc(size);
	if (buffer == NULL)
	{
		fprintf(stderr, "Memory allocation error\n");
		return SSH_ERROR;
	}
	ssh_scp_accept_request(scp);
	rc = ssh_scp_read(scp, buffer, size);
	if (rc == SSH_ERROR)
	{
		fprintf(stderr, "Error receiving file data: %s\n",
			ssh_get_error(session));
		free(buffer);
		return rc;
	}
	printf("Done\n");
	write(1, buffer, size);
	free(buffer);
	rc = ssh_scp_pull_request(scp);
	if (rc != SSH_SCP_REQUEST_EOF)
	{
		fprintf(stderr, "Unexpected request: %s\n",
			ssh_get_error(session));
		return SSH_ERROR;
	}
	return SSH_OK;
}

int scp_read(ssh_session session) {
	ssh_scp scp;
	int rc;
	scp = ssh_scp_new
	(session, SSH_SCP_READ, "downloads/FilmMover/file.txt");
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
	
	if (scp_receive(session, scp) != SSH_OK) {
		printf("Error: %s\n", ssh_get_error(session));
	}

	ssh_scp_close(scp);
	ssh_scp_free(scp);
	return SSH_OK;
}

int main()
{
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
	char *host;
	printf("Host: ");
	reader(stdin, &host);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, host);
	free(host);

	printf("User: ");
	reader(stdin, &host);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, host);
	free(host);

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
	char *password = getpass("Password: ");
	rc = ssh_userauth_password(my_ssh_session, NULL, password);
	if (rc != SSH_AUTH_SUCCESS)
	{
		fprintf(stderr, "Error authenticating with password: %s\n",
			ssh_get_error(my_ssh_session));
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		exit(-1);
	}

	scp_read(my_ssh_session);

	ssh_disconnect(my_ssh_session);
	ssh_free(my_ssh_session);
}
