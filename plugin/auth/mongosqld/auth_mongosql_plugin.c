/*
 * Copyright 2017 MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <my_global.h>
#include <mysql/plugin_auth.h>
#include <mysql/client_plugin.h>
#include <mysql/service_my_plugin_log.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <mysql.h>
#include "bson.h"
#include "mongoc-scram-private.h"
#include "mongo-scram.c"

#define MAX_MECHANISM_LENGTH 1024

/**
  Authenticate the client using the MongoDB MySQL Authentication Plugin Protocol.
 
  @param vio Provides plugin access to communication channel
  @param mysql Client connection handler

  @return Error status
    @retval CR_ERROR An error occurred.
    @retval CR_OK Authentication succeeded.
*/
static int mongosql_plugin_client(MYSQL_PLUGIN_VIO *vio, MYSQL_SERVER_AUTH_INFO *info)
{
  uint32_t buflen = 0;
  mongoc_scram_t scram;
  const char *tmpstr;
  const char *auth_source;
  uint8_t buf[4096] = {0};
  int conv_id = 0;
  bson_error_t error;

  unsigned char *pkt;
  int pkt_len;

  unsigned char *mechanism;
  int32_t num_conversations;

  /* write 0 bytes */
  if (vio->write_packet(vio, (const unsigned char *) {0}, 1))
    return CR_ERROR;


  /* read server reply */
  if ((pkt_len= vio->read_packet(vio, &pkt)) < 0)
    return CR_ERROR;

  /*
    Copy the mechanism and iteration count
  */
  mechanism = pkt;
  memcpy(&num_conversations, pkt+strlen((const char *)mechanism)+1, 4);

  fprintf(stderr, "MECHANISM IS '%s'", *mechanism);

   /*

   if (!(auth_source = mongoc_uri_get_auth_source (cluster->uri)) ||
       (*auth_source == '\0')) {
      auth_source = "admin";
   }
   */
   auth_source = "admin";

   _mongoc_scram_init (&scram);

   /*
   _mongoc_scram_set_pass (&scram, mongoc_uri_get_password (cluster->uri));
   _mongoc_scram_set_user (&scram, mongoc_uri_get_username (cluster->uri));
   */

   _mongoc_scram_set_pass (&scram, info->auth_string);
   _mongoc_scram_set_user (&scram, info->user_name);


   for (;;) {
      if (!_mongoc_scram_step (
             &scram, buf, buflen, buf, sizeof buf, &buflen, &error)) {
         goto failure;
      }

      if (vio->write_packet(vio, (const unsigned char *) buf, buflen))
          return CR_ERROR;

      fprintf(stderr, "SCRAM: authenticating (step %d)", scram.step);
   }

   fprintf(stderr, "%s", "SCRAM: authenticated");

failure:
   _mongoc_scram_destroy (&scram);

   return CR_OK;
}


mysql_declare_client_plugin(AUTHENTICATION)
  "mongosql_plugin_client",
  "MongoDB",
  "MongoDB MySQL Authentication Plugin",
  {0,1,0},
  "GPL",
  NULL,
  NULL,
  NULL,
  NULL,
  mongosql_plugin_client
mysql_end_client_plugin;
