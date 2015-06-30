#define USER "student2"
//#define PWD "asdfghjkl"
#define PWD "memwax64"
#define MAX_XFER_BUF_SIZE 16384
#define CMD "./tre_ext -n %d -m %d -i ran_input -a 0.5 -e 0.001 -o ran_output -v"
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <sys/file.h>
#include <stdlib.h>
#include <stdio.h>
#include "ext.h"
#include <errno.h>
#include <string.h>

int verify_knownhost(ssh_session session);

ssh_session my_ssh_init();

void ssh_destroy();

int exec_cmd(ssh_session session, char* cmd); 

int exec_ext(ssh_session session, n, m);

int exec_rm(ssh_session); 

int sftp_read_sync(ssh_session session, sftp_session sftp,
		   int out_len, unsigned char* output);

int sftp_upload_sync(ssh_session session, sftp_session sftp,
		     unsigned char* input); 

unsigned char* ext(unsigned char* input, int crude_len, int out_len) {
  ssh_session my_ssh_session = my_ssh_init();
  sftp_session my_sftp_session = sftp_new(my_ssh_session);
  sftp_init(my_sftp_session);
  exec_rm(my_ssh_session); 
  sftp_upload_sync(my_ssh_session, my_sftp_session, input);
  exec_ext(my_ssh_session, crude_len, out_len);
  char* output; 
  sftp_read_sync(my_ssh_session, my_sftp_session, out_len, output); 
  sftp_free(my_sftp_session); 
  ssh_destroy(my_ssh_session);
  return output; 
} 

ssh_session my_ssh_init()
{
  ssh_session my_ssh_session;
  int rc;
  char *password;
  // Open session and set options
  my_ssh_session = ssh_new();
  if (my_ssh_session == NULL)
    exit(-1);
  ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "166.111.142.77");
  ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, USER); 
  // Connect to server
  rc = ssh_connect(my_ssh_session);
  if (rc != SSH_OK) {
    fprintf(stderr, "Error connecting to localhost: %s\n",
	    ssh_get_error(my_ssh_session));
    ssh_free(my_ssh_session);
    exit(-1);
  }
  // Verify the server's identity
  // For the source code of verify_knowhost(), check previous example
  if (verify_knownhost(my_ssh_session) < 0) {
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    exit(-1);
  }
  // Authenticate ourselves
  // password = getpass("Password: ");
  password = PWD; 
  rc = ssh_userauth_password(my_ssh_session, NULL, password);
  if (rc != SSH_AUTH_SUCCESS) {
    fprintf(stderr, "Error authenticating with password: %s\n",
	    ssh_get_error(my_ssh_session));
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    exit(-1);
  }
  return my_ssh_session; 
}

void ssh_destroy(ssh_session my_ssh_session) {
  ssh_disconnect(my_ssh_session);
  ssh_free(my_ssh_session);
} 

int verify_knownhost(ssh_session session)
{
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
      fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
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

int sftp_read_sync(ssh_session session, sftp_session sftp,
		   int out_len, unsigned char* output)
{
  int access_type;
  sftp_file file;
  char buffer[MAX_XFER_BUF_SIZE];
  output = malloc(out_len); 
  int nbytes, nwritten, rc;
  int fd;
  access_type = O_RDONLY;
  file = sftp_open(sftp, "/home/student2/ran_output",
                   access_type, 0);
  if (file == NULL) {
      fprintf(stderr, "Can't open file for reading: %s\n",
              ssh_get_error(session));
      return SSH_ERROR;
  }
  fd = open("ran_output", O_CREAT|O_WRONLY|O_RDONLY);
  if (fd < 0) {
      fprintf(stderr, "Can't open file for writing: %s\n",
              strerror(errno));
      return SSH_ERROR;
  }
  for (int read = 0;;) {
    nbytes = sftp_read(file, &output[read], sizeof(buffer));
    if (nbytes == 0) {
      break; // EOF
    } else {
      read += nbytes;
    } 
    /* else if (nbytes < 0) { */
      /*     fprintf(stderr, "Error while reading file: %s\n", */
      /*             ssh_get_error(session)); */
      /*     sftp_close(file); */
      /*     return SSH_ERROR; */
      /* } */
      /* nwritten = write(fd, buffer, nbytes); */
      /* if (nwritten != nbytes) { */
      /*     fprintf(stderr, "Error writing: %s\n", */
      /*             strerror(errno)); */
      /*     sftp_close(file); */
      /*     return SSH_ERROR; */
      /* } */
      
  }
  rc = sftp_close(file);
  if (rc != SSH_OK) {
      fprintf(stderr, "Can't close the read file: %s\n",
              ssh_get_error(session));
      return rc;
  }
  return SSH_OK;
}

int sftp_upload_sync(ssh_session session, sftp_session sftp, unsigned char* input)
{
  int access_type = O_WRONLY | O_CREAT | O_TRUNC;
  sftp_file file;
  int length = strlen(input);
  int rc, nwritten;
  file = sftp_open(sftp, "ran_input",
                   access_type, S_IRWXU);
  if (file == NULL)
  {
    fprintf(stderr, "Can't open file for writing: %s\n",
            ssh_get_error(session));
    return SSH_ERROR;
  }
  nwritten = sftp_write(file, input, length);
  if (nwritten != length)
  {
    fprintf(stderr, "Can't write data to file: %s\n",
            ssh_get_error(session));
    sftp_close(file);
    return SSH_ERROR;
  }
  rc = sftp_close(file);
  if (rc != SSH_OK)
  {
    fprintf(stderr, "Can't close the written file: %s\n",
            ssh_get_error(session));
    return rc;
  }
  return SSH_OK;
}

int exec_cmd(ssh_session session, char* cmd)
{
  ssh_channel channel;
  int rc;
  char buffer[256];
  unsigned int nbytes;
  channel = ssh_channel_new(session);
  if (channel == NULL)
    return SSH_ERROR;
  rc = ssh_channel_open_session(channel);
  if (rc != SSH_OK)
  {
    ssh_channel_free(channel);
    return rc;
  }
  rc = ssh_channel_request_exec(channel, cmd);
  if (rc != SSH_OK)
  {
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return rc;
  }
  nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  while (nbytes > 0)
  {
    if (write(1, buffer, nbytes) != nbytes)
    {
      ssh_channel_close(channel);
      ssh_channel_free(channel);
      return SSH_ERROR;
    }
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  }
    
  if (nbytes < 0)
  {
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return SSH_ERROR;
  }
  ssh_channel_send_eof(channel);
  ssh_channel_close(channel);
  ssh_channel_free(channel);
  return SSH_OK;
}

int exec_ext(ssh_session session, int n, int m)
{
  char cmd[100];
  sprintf(cmd, CMD, n * 8, m * 8);
  printf("&s\n", cmd);
  exec_cmd(session, cmd);
  return SSH_OK; 
}

int exec_rm(ssh_session session) {
  exec_cmd(session, "rm ran_input");
  return SSH_OK; 
} 
