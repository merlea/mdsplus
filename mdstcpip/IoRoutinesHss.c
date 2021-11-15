/*
Copyright (c) 2017, Massachusetts Institute of Technology All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

Redistributions in binary form must reproduce the above copyright notice, this
list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// Undefine symbols defined again in config.h
#ifdef HAVE_STDARG_H
#undef HAVE_STDARG_H
#endif
#ifdef HAVE_GETADDRINFO
#undef HAVE_GETADDRINFO
#endif
#ifdef HAVE_GETPWUID
#undef HAVE_GETPWUID
#endif
#ifdef _GNU_SOURCE
#undef _GNU_SOURCE
#endif
#ifdef SIZEOF_LONG
#undef SIZEOF_LONG
#endif

#include <STATICdef.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <mdsplus/mdsconfig.h>
#include <mdsshr.h>
#include <signal.h>
#include <status.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <time.h>

#include "mdsip_connections.h"

#include <libssh/libssh.h>

static ssize_t hss_send(Connection *c, const void *buffer, size_t buflen,
                        int nowait);
static ssize_t hss_recv(Connection *c, void *buffer, size_t len);
static int hss_disconnect(Connection *c);
static int hss_connect(Connection *c, char *protocol, char *host);

const IoRoutines hss_routines = {
    hss_connect, hss_send, hss_recv, NULL,
    NULL       , NULL       , NULL       , hss_disconnect,
    NULL, NULL};

static int dbg =0;

EXPORT IoRoutines *Io() { return &hss_routines; }

/* authentication.c
 * This file contains an example of how to do an authentication to a
 * SSH server using libssh
 * Copyright 2003-2009 Aris Adamantiadis
 */
static int authenticate_kbdint(ssh_session session, const char *password) {
    int err;

    err = ssh_userauth_kbdint(session, NULL, NULL);
    while (err == SSH_AUTH_INFO) {
        const char *instruction;
        const char *name;
        char buffer[128];
        int i, n;

        name = ssh_userauth_kbdint_getname(session);
        instruction = ssh_userauth_kbdint_getinstruction(session);
        n = ssh_userauth_kbdint_getnprompts(session);
        if (name && strlen(name) > 0) {
            printf("%s\n", name);
        }
        if (instruction && strlen(instruction) > 0) {
            printf("%s\n", instruction);
        }
        for (i = 0; i < n; i++) {
            const char *answer;
            const char *prompt;
            char echo;
            prompt = ssh_userauth_kbdint_getprompt(session, i, &echo);
            if (prompt == NULL) {
                break;
            }
            if (echo) {
                char *p;
                printf("%s", prompt);
                if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
                    return SSH_AUTH_ERROR;
                }
                buffer[sizeof(buffer) - 1] = '\0';
                if ((p = strchr(buffer, '\n'))) {
                    *p = '\0';
                }
                if (ssh_userauth_kbdint_setanswer(session, i, buffer) < 0) {
                    return SSH_AUTH_ERROR;
                }
                memset(buffer, 0, strlen(buffer));
            } else {
                if (password && strstr(prompt, "Password:")) {
                    answer = password;
                } else {
                    buffer[0] = '\0';

                    if (ssh_getpass(prompt, buffer, sizeof(buffer), 0, 0) < 0) {
                        return SSH_AUTH_ERROR;
                    }
                    answer = buffer;
                }
                err = ssh_userauth_kbdint_setanswer(session, i, answer);
                memset(buffer, 0, sizeof(buffer));
                if (err < 0) {
                    return SSH_AUTH_ERROR;
                }
            }
        }
        err=ssh_userauth_kbdint(session,NULL,NULL);
    }
    return err;
}

static int auth_keyfile(ssh_session session, char* keyfile) {
    ssh_key key = NULL;
    char pubkey[132] = {0}; // +".pub"
    int rc;

    snprintf(pubkey, sizeof(pubkey), "%s.pub", keyfile);
    rc = ssh_pki_import_pubkey_file( pubkey, &key);
    if (rc != SSH_OK)
        return SSH_AUTH_DENIED;
    rc = ssh_userauth_try_publickey(session, NULL, key);
    ssh_key_free(key);
    if (rc!=SSH_AUTH_SUCCESS)
        return SSH_AUTH_DENIED;
    rc = ssh_pki_import_privkey_file(keyfile, NULL, NULL, NULL, &key);
    if (rc != SSH_OK)
        return SSH_AUTH_DENIED;
    rc = ssh_userauth_publickey(session, NULL, key);
    ssh_key_free(key);
    return rc;
}


static void error(ssh_session session) {
    printf("Authentication failed: %s\n",ssh_get_error(session));
}

static int authenticate_console(ssh_session session) {
    int rc;
    int method;
    char password[128] = {0};
    char *banner;
    char *fpub  = NULL;
    char *fprv  = NULL;
    char *fuser = NULL;

    // Try to authenticate
    rc = ssh_userauth_none(session, NULL);
    if(dbg)
        printf("ssh_userauth_none [%d,%d]\n",rc,SSH_AUTH_ERROR);
    if (rc == SSH_AUTH_ERROR) {
        error(session);
        return rc;
    }
    // look to see is share variables have been defined 
    banner = getenv("HSS_USER");
    if(banner != NULL){
        fuser = malloc(strlen(banner)+1);
        strcpy(fuser, banner);
    }
    banner = getenv("HSS_KEY");
    if(banner != NULL){
        fprv = malloc(strlen(banner)+1);
        strcpy(fprv, banner);
        fpub = malloc(strlen(banner)+5);
        strcpy(fpub, banner);
        strcat(fpub, ".pub");
    }
    // make attempt for JET only (define HSS_USER HSS_KEY)
    if(fpub != NULL && fuser != NULL) {
        ssh_key ppkey, pukey;

  //ssh_options_set(s, SSH_OPTIONS_USER, "bpduval" );
        method = ssh_userauth_list(session, NULL);
        // Try to authenticate with given public key
        if (method & SSH_AUTH_METHOD_PUBLICKEY) {
            rc = ssh_pki_import_pubkey_file(fpub, &ppkey);
            if(dbg)
                printf("ok [%d]-pubkeyImport result [%d]\n",SSH_OK,rc);
            rc = ssh_userauth_try_publickey(session, NULL, ppkey);
            if(dbg)
                printf("pubkeyTry result [%d]\n",rc);
            rc = ssh_pki_import_privkey_file(fprv, NULL, NULL, NULL, &pukey);
            if(dbg)
                printf("priveImport result [%d]\n",rc);
            rc = ssh_userauth_publickey(session, NULL, pukey);
            if(dbg)
                printf("priveAuth result [%d]\n",rc);
            ssh_key_free(ppkey);
            ssh_key_free(pukey);
            if(rc != SSH_OK ) {
                if(dbg)
                    printf("Auth failed [%d]\n",rc);
                return(-1);
            }
        }
    } else {
        method = ssh_userauth_list(session, NULL);
        while (rc != SSH_AUTH_SUCCESS) {
            if (method & SSH_AUTH_METHOD_GSSAPI_MIC){
                rc = ssh_userauth_gssapi(session);
                if(rc == SSH_AUTH_ERROR) {
                    error(session);
                    return rc;
                } else if (rc == SSH_AUTH_SUCCESS) {
                    break;
                }
            }
            // Try to authenticate with public key first
            if (method & SSH_AUTH_METHOD_PUBLICKEY) {
                rc = ssh_userauth_publickey_auto(session, NULL, NULL);
                if(dbg)
                    printf("ssh_userauth_publickey_auto [%d,%d]\n",rc,SSH_AUTH_ERROR);
                if (rc == SSH_AUTH_ERROR) {
                    error(session);
                    return rc;
                } else if (rc == SSH_AUTH_SUCCESS) {
                    break;
                }
            }
            {
                char buffer[128] = {0};
                char *p = NULL;

                printf("Automatic pubkey failed. "
                        "Do you want to try a specific key? (y/n)\n");
                if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
                    break;
                }
                if ((buffer[0]=='Y') || (buffer[0]=='y')) {
                    printf("private key filename: ");
                    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
                        return SSH_AUTH_ERROR;
                    }
                    buffer[sizeof(buffer) - 1] = '\0';
                    if ((p = strchr(buffer, '\n'))) {
                        *p = '\0';
                    }
                    rc = auth_keyfile(session, buffer);
                    if(rc == SSH_AUTH_SUCCESS) {
                        break;
                    }
                    fprintf(stderr, "failed with key\n");
                }
            }
            // Try to authenticate with keyboard interactive";
            if (method & SSH_AUTH_METHOD_INTERACTIVE) {
                rc = authenticate_kbdint(session, NULL);
                if (rc == SSH_AUTH_ERROR) {
                    error(session);
                    return rc;
                } else if (rc == SSH_AUTH_SUCCESS) {
                    break;
                }
            }
            if (ssh_getpass("Password: ", password, sizeof(password), 0, 0) < 0) {
                return SSH_AUTH_ERROR;
            }
            // Try to authenticate with password
            if (method & SSH_AUTH_METHOD_PASSWORD) {
                rc = ssh_userauth_password(session, NULL, password);
                if (rc == SSH_AUTH_ERROR) {
                    error(session);
                    return rc;
                } else if (rc == SSH_AUTH_SUCCESS) {
                    break;
                }
            }
            memset(password, 0, sizeof(password));
        }
        banner = ssh_get_issue_banner(session);
        if (banner) {
            printf("%s\n",banner);
            SSH_STRING_FREE_CHAR(banner);
        }
    }
    if(fuser != NULL) free(fuser);
    if(fprv  != NULL) free(fprv);
    if(fpub  != NULL) free(fpub);
    return rc;
}

/* knownhosts.c
 * This file contains an example of how verify the identity of a
 * SSH server using libssh
 * Copyright 2003-2009 Aris Adamantiadis
 */
static int verify_knownhost(ssh_session session) {
    enum ssh_known_hosts_e state;
    char buf[10];
    unsigned char *hash = NULL;
    size_t hlen;
    ssh_key srv_pubkey;
    int rc;

    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < 0) {
        return -1;
    }

    rc = ssh_get_publickey_hash(srv_pubkey,
                                SSH_PUBLICKEY_HASH_SHA256,
                                &hash,
                                &hlen);
    ssh_key_free(srv_pubkey);
    if (rc < 0) {
        return -1;
    }
    state = ssh_session_is_known_server(session);
    switch(state) {
    case SSH_KNOWN_HOSTS_CHANGED:
        fprintf(stderr,"Host key for server changed : server's one is now :\n");
        ssh_print_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);
        ssh_clean_pubkey_hash(&hash);
        fprintf(stderr,"For security reason, connection will be stopped\n");
        return -1;
    case SSH_KNOWN_HOSTS_OTHER:
        fprintf(stderr,"The host key for this server was not found but an other type of key exists.\n");
        fprintf(stderr,"An attacker might change the default server key to confuse your client"
                "into thinking the key does not exist\n"
                "We advise you to rerun the client with -d or -r for more safety.\n");
        return -1;
    case SSH_KNOWN_HOSTS_NOT_FOUND:
        fprintf(stderr,"Could not find known host file. If you accept the host key here,\n");
        fprintf(stderr,"the file will be automatically created.\n");
        /* fallback to SSH_SERVER_NOT_KNOWN behavior */
        //FALL_THROUGH;
    case SSH_SERVER_NOT_KNOWN:
        fprintf(stderr,
                "The server is unknown. Do you trust the host key (yes/no)?\n");
        ssh_print_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);

        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            ssh_clean_pubkey_hash(&hash);
            return -1;
        }
        if(strncasecmp(buf,"yes",3)!=0){
            ssh_clean_pubkey_hash(&hash);
            return -1;
        }
        fprintf(stderr,"This new key will be written on disk for further usage. do you agree ?\n");
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
            ssh_clean_pubkey_hash(&hash);
            return -1;
        }
        if(strncasecmp(buf,"yes",3)==0){
            rc = ssh_session_update_known_hosts(session);
            if (rc != SSH_OK) {
                ssh_clean_pubkey_hash(&hash);
                fprintf(stderr, "error %s\n", strerror(errno));
                return -1;
            }
        }
        break;
    case SSH_KNOWN_HOSTS_ERROR:
        ssh_clean_pubkey_hash(&hash);
        fprintf(stderr,"%s",ssh_get_error(session));
        return -1;
    case SSH_KNOWN_HOSTS_OK:
        break; /* ok */
    }
    ssh_clean_pubkey_hash(&hash);
    return 0;
}

static int GetPort(char *pname) {
  short port;
  char *name = pname ? pname : GetPortname();
  struct servent *sp;
  if (name == 0 || strcmp(name, "mdsip") == 0)
    name = "mdsips";
  port = htons((short)strtol(name, NULL, 0));
  if (port == 0) {
    sp = getservbyname(name, "tcp");
    if (sp == NULL) {
      fprintf(stderr, "unknown service: %s/tcp\n\n", name);
      exit(0);
    }
    port = sp->s_port;
  }
  return ntohs(port);
}

static ssh_channel *getHssInfoC(Connection *c) {
  size_t len;
  char *info_name;
  int readfd;
  ssh_channel *info = (ssh_channel *)GetConnectionInfoC(c, &info_name, &readfd, &len);
  return (info_name && strcmp(info_name, "hss") == 0) && len == sizeof(ssh_channel)
             ? info
             : 0;
}

static ssize_t hss_send(Connection *c, const void *bptr, size_t num,
                        int options __attribute__((unused))) {
  ssh_channel *info = getHssInfoC(c);
  ssize_t sent = -1;
  if (info != NULL) {
      sent = ssh_channel_write(*info, bptr, num);
  }
  return sent;
}

static ssize_t hss_recv(Connection *c, void *bptr, size_t num) {
  ssh_channel *info = getHssInfoC(c);
  ssize_t recved = -1;
  if (info != 0) {
      recved = ssh_channel_read(*info, bptr, num, 0);
  }
  return recved;
}

static int hss_disconnect(Connection *c) {
  ssh_channel *info = NULL;
  ssh_session s = NULL;
  char now[32];
  if(c == NULL) {
          printf("called hss_disconnect with NULL\n");
          return SSH_OK;
  }
  if( (info = getHssInfoC(c)) != NULL) {
      s = ssh_channel_get_session(*info);
  } else {
      printf("hss_disconnect [%lu] NULL info\n",(unsigned long)c);
      return SSH_OK;
  }
  if(dbg)
      printf("Called hss_disconnect with [%lu,%lu,%lu]\n",(unsigned long)c, (unsigned long)info, (unsigned long)s);
  if (info != NULL) {
#ifndef NEVER
      ssh_channel_send_eof(*info);
      ssh_channel_close(*info);
      ssh_channel_free(*info);
#else
      ssh_silent_disconnect(s);
#endif
      free(info);
  }
  if ( s != NULL ) {
      ssh_disconnect(s);
      ssh_free(s);
  }
  SetConnectionInfoC(c, "hss", 0, NULL, 0);
  Now32(now);
#ifdef NEVER
  printf("%s (pid %d) Connection disconnected from %s\r\n", now, getpid(),
          ssh_get_serverbanner(s));
#else
  printf("%s (pid %d) Connection disconnected \n", now, getpid());
#endif
  return SSH_OK;
}

#include <libssh/callbacks.h>
static int hss_once = 1;
static int hss_connect(Connection *c, char *protocol __attribute__((unused)),
        char *host_in) {
  int port, rc;
  char *buffer = ". /etc/profile; mdsip-server-ssh";
  char *contact_string;
  char *portname;
  char *colon;
  char *host =
      host_in ? strcpy((char *)malloc(strlen(host_in) + 1), host_in) : 0;
  ssh_session s;
  ssh_channel info;
  if (!host)
    return C_ERROR;
  if ((colon = strchr(host, ':')) != 0) {
    *colon = 0;
    portname = colon + 1;
  } else {
    portname = "ssh";
  }
  port = GetPort(portname);
  // start new session with remote machine
  if(hss_once) {
      ssh_threads_set_callbacks(ssh_threads_get_pthread());
      ssh_init();
      hss_once=0;
  }
  s = ssh_new();
  ssh_options_set(s, SSH_OPTIONS_HOST, host);
  ssh_options_set(s, SSH_OPTIONS_PORT, &port );
//  ssh_options_set(s, SSH_OPTIONS_USER, "bpduval" );
  rc = ssh_connect(s);
  if(rc != SSH_OK) {
      if(dbg)
          printf("connect ssh_connect FAIL [%s] [%s]\n",host,ssh_get_error(s));
      ssh_free(s);
      return(C_ERROR);
  }
  if(verify_knownhost(s) < 0) {     // check host known
      if(dbg)
          printf("connect verify_knownhosts FAIL\n");
      ssh_disconnect(s);
      free(s);
      return(C_ERROR);
  }
  if(authenticate_console(s) < 0) {
      if(dbg)
          printf("connect authenticate_console FAIL\n");
      ssh_disconnect(s);
      free(s);
      return(C_ERROR);
  }
  info = ssh_channel_new(s);
  if (info == NULL) {
      if(dbg)
          printf("connect ssh_channel_new FAIL\n");
      return(C_ERROR);
  }
  ssh_channel_open_session(info);
  if (ssh_channel_request_exec(info, buffer)) {
      if(dbg)
          printf("Error executing '%s' : %s\n", buffer, ssh_get_error(info));
      ssh_channel_free(info);
      return(C_ERROR);
  }

  contact_string = (char *)malloc(strlen(host) + 50);
  sprintf(contact_string, "%s:%d", host, GetPort(portname));
  free(host);

  SetConnectionInfoC(c, "hss", 0, &info, sizeof(info));
  return C_OK;
}
