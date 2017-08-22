/*****************************************************************************
 *
 * ALERTA-NEB.C
 *
 *     $ indent -br -nut -l125 alerta-neb.c
 *
 *****************************************************************************/

#include <string.h>

#include "config.h"

#include "nebmodules.h"
#include "nebcallbacks.h"

#include "nebstructs.h"
#include "neberrors.h"
#include "broker.h"

#include "config.h"
#include "common.h"
#include "nagios.h"

#include "uthash.h"

#include <curl/curl.h>

NEB_API_VERSION (CURRENT_NEB_API_VERSION);

char *VERSION = "3.4.1";

void *alerta_module_handle = NULL;

int check_handler (int, void *);

int debug = 0;

char message[4096];
char hostname[1024];
char alert_url[1024];
char heartbeat_url[1024];
char auth_header[1024];
char environment[1024] = "Production";
char hard_states_only = 0;

static CURL *curl = NULL;

typedef struct downtime_struct {
    char key[2048];
    int id;
    UT_hash_handle hh;
} downtime;

downtime *downtimes = NULL;

const char *
display_evt_type (int type)
{
  switch (type) {
  case NEBTYPE_HOSTCHECK_INITIATE:
  case NEBTYPE_HOSTCHECK_PROCESSED:
  case NEBTYPE_HOSTCHECK_RAW_START:
  case NEBTYPE_HOSTCHECK_RAW_END:
  case NEBTYPE_HOSTCHECK_ASYNC_PRECHECK:
  case NEBTYPE_HOSTCHECK_SYNC_PRECHECK:
    return ("HostCheck");
  case NEBTYPE_SERVICECHECK_INITIATE:
  case NEBTYPE_SERVICECHECK_PROCESSED:
  case NEBTYPE_SERVICECHECK_RAW_START:
  case NEBTYPE_SERVICECHECK_RAW_END:
  case NEBTYPE_SERVICECHECK_ASYNC_PRECHECK:
    return ("ServiceCheck");
  default:
    return ("UnknownType");
  }
}

const char *
display_evt_class (int class)
{
  switch (class) {
  case NEBTYPE_HOSTCHECK_INITIATE:
  case NEBTYPE_SERVICECHECK_INITIATE:
    return ("Initiate");
  case NEBTYPE_HOSTCHECK_PROCESSED:
  case NEBTYPE_SERVICECHECK_PROCESSED:
    return ("Processed");
  case NEBTYPE_HOSTCHECK_RAW_START:
  case NEBTYPE_SERVICECHECK_RAW_START:
    return ("RawStart");
  case NEBTYPE_HOSTCHECK_RAW_END:
  case NEBTYPE_SERVICECHECK_RAW_END:
    return ("RawEnd");
  case NEBTYPE_HOSTCHECK_ASYNC_PRECHECK:
  case NEBTYPE_SERVICECHECK_ASYNC_PRECHECK:
    return ("AsyncPrecheck");
  case NEBTYPE_HOSTCHECK_SYNC_PRECHECK:
    return ("SyncPrecheck");
  default:
    return ("UnknownType");
  }
}

const char *
display_state (int state)
{
  switch (state) {
  case STATE_OK:
    return ("normal");
  case STATE_WARNING:
    return ("warning");
  case STATE_CRITICAL:
    return ("critical");
  case STATE_UNKNOWN:
  default:
    return ("unknown");
  }
}

const char *
display_state_type (int state_type)
{
  switch (state_type) {
  case SOFT_STATE:
    return ("Soft");
  case HARD_STATE:
    return ("Hard");
  default:
    return ("Unknown");
  }
}

const char *
display_check_type (int check_type)
{
  switch (check_type) {
    // case HOST_CHECK_ACTIVE:
  case SERVICE_CHECK_ACTIVE:
    return ("Active");
    // case HOST_CHECK_PASSIVE:
  case SERVICE_CHECK_PASSIVE:
    return ("Passive");
  default:
    return ("Unknown");
  }
}

const char *
display_downtime_type (int downtime_type)
{
  switch (downtime_type) {
  case SERVICE_DOWNTIME:
    return ("Service Downtime");
  case HOST_DOWNTIME:
    return ("Host Downtime");
  default:
    return ("Host or Service Downtime");
  }
}

char *
replace_char(const char *input_string, char old_char, const char *new_string) {
    int count = 0;
    const char *t;
    for(t=input_string; *t; t++)
        count += (*t == old_char);

    size_t rlen = strlen(new_string);
    char *output_string = malloc(strlen(input_string) + (rlen-1)*count + 1);
    char *ptr = output_string;
    for(t=input_string; *t; t++) {
        if(*t == old_char) {
            memcpy(ptr, new_string, rlen);
            ptr += rlen;
        } else {
            *ptr++ = *t;
        }
    }
    *ptr = 0;
    return output_string;
}

int
log_debug(char *message)
{
  if (debug)
    write_to_all_logs (message, NSLOG_INFO_MESSAGE);
}

int
log_info(char *message)
{
  write_to_all_logs (message, NSLOG_INFO_MESSAGE);
}

int
log_warning(char *message)
{
  write_to_all_logs (message, NSLOG_RUNTIME_WARNING);
}

int
log_config(char *message)
{
  write_to_all_logs (message, NSLOG_CONFIG_ERROR);
}

int
log_error(char *message)
{
  write_to_all_logs(message, NSLOG_RUNTIME_ERROR);
}

int
send_to_alerta(char *url, char *message)
{
  CURLcode res;
  long status;

  if (curl == NULL) {
      curl = curl_easy_init ();
  } else {
      curl_easy_reset (curl);
  }

  if (!curl) {
    return NEB_ERROR;
  }

  char *message_mod = replace_char(message, '\\', " ");  // avoid broken JSON output

  log_debug (message);

  struct curl_slist *headers = NULL;
  headers = curl_slist_append (headers, "Content-Type: application/json");
  if (strlen(auth_header))
    headers = curl_slist_append (headers, auth_header);
  curl_easy_setopt (curl, CURLOPT_URL, url);
  curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt (curl, CURLOPT_POSTFIELDS, message_mod);
  res = curl_easy_perform (curl);
  curl_slist_free_all(headers);

  if (res != CURLE_OK) {
    sprintf (message, "[alerta] curl_easy_perform() failed: %s", curl_easy_strerror (res));
    log_error (message);
    return res;
  }
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

  switch (status) {
  case 200:
  case 201:
    sprintf (message, "[alerta] HTTP response OK (status=%ld)", status);
    log_debug (message);
    break;
  case 202:
    sprintf (message, "[alerta] HTTP request ignored during blackout period. (status=%ld)", status);
    log_warning (message);
    break;
  case 401:
    sprintf (message, "[alerta] HTTP auth error. API key not configured? (status=%ld)", status);
    log_config (message);
    break;
  case 403:
    sprintf (message, "[alerta] HTTP request forbidden or rejected. (status=%ld)", status);
    log_config (message);
    break;
  case 429:
    sprintf (message, "[alerta] HTTP request rate limited. Too many alerts? (status=%ld)", status);
    log_error (message);
    break;
  default:
    sprintf (message, "[alerta] HTTP server error (status=%ld)", status);
    log_error (message);
    break;
  }
  return status;
}

int
nebmodule_init (int flags, char *args, nebmodule * handle)
{
  time_t clock;
  unsigned long interval;
  gethostname (hostname, 1023);

  alerta_module_handle = handle;        /* save the neb module handle */

  neb_set_module_info (alerta_module_handle, NEBMODULE_MODINFO_TITLE, "Nagios-Alerta Gateway");
  neb_set_module_info (alerta_module_handle, NEBMODULE_MODINFO_AUTHOR, "Nick Satterly");
  neb_set_module_info (alerta_module_handle, NEBMODULE_MODINFO_COPYRIGHT, "Copyright (c) 2015-2017 Nick Satterly");
  neb_set_module_info (alerta_module_handle, NEBMODULE_MODINFO_VERSION, VERSION);
  neb_set_module_info (alerta_module_handle, NEBMODULE_MODINFO_LICENSE, "MIT License");
  neb_set_module_info (alerta_module_handle, NEBMODULE_MODINFO_DESC,
                       "Nagios Event Broker module that forwards Nagios events to Alerta");

  sprintf (message, "[alerta] Initialising Nagios-Alerta Gateway module, v%s", VERSION);
  log_info (message);

  char endpoint[1024] = "";
  char key[1024] = "";
  char *token;
  while ((token = strsep (&args, " ")) != NULL) {
    if (strncasecmp (token, "http://", 7) == 0)
      strcpy (endpoint, token);
    if (strncasecmp (token, "https://", 8) == 0)
      strcpy (endpoint, token);
    if (strncasecmp (token, "env=", 4) == 0)
      strcpy (environment, token+4);
    if (strncasecmp (token, "key=", 4) == 0)
      strcpy (key, token+4);
    if (strncasecmp (token, "debug=1", 7) == 0)
      debug = 1;
    if (strncasecmp (token, "hard_only=1", 11) == 0)
      hard_states_only = 1;
  }
  if (strlen(endpoint)) {
    sprintf (alert_url, "%s/alert", endpoint);
    sprintf (heartbeat_url, "%s/heartbeat", endpoint);
    if (strlen(key))
      sprintf (auth_header, "Authorization: Key %s", key);
  } else {
    log_config ("[alerta] API endpoint not configured.");
    exit(1);
  }

  if (debug)
    log_info ("[alerta] debug is on");
  else
    log_info ("[alerta] debug is off");

  if (hard_states_only)
    log_info ("[alerta] states=Hard (only)");
  else
    log_info ("[alerta] states=Hard/Soft");

  curl_global_init (CURL_GLOBAL_ALL);

  neb_register_callback (NEBCALLBACK_HOST_CHECK_DATA, alerta_module_handle, 0, check_handler);
  neb_register_callback (NEBCALLBACK_SERVICE_CHECK_DATA, alerta_module_handle, 0, check_handler);
  neb_register_callback (NEBCALLBACK_DOWNTIME_DATA, alerta_module_handle, 0, check_handler);

  sprintf (message, "[alerta] Forward service checks, host checks and downtime to %s", endpoint);
  log_info (message);

  return NEB_OK;
}

int
nebmodule_deinit (int flags, int reason)
{
  curl_global_cleanup ();

  neb_deregister_callback (NEBCALLBACK_HOST_CHECK_DATA, check_handler);
  neb_deregister_callback (NEBCALLBACK_SERVICE_CHECK_DATA, check_handler);
  neb_deregister_callback (NEBCALLBACK_DOWNTIME_DATA, check_handler);

  log_info ("[alerta] NEB callbacks for host and service checks successfully de-registered. Bye.");

  return NEB_OK;
}

int
check_handler (int event_type, void *data)
{
  nebstruct_host_check_data *host_chk_data = NULL;
  nebstruct_service_check_data *svc_chk_data = NULL;
  nebstruct_downtime_data *downtime_data = NULL;

  char cov_environment[1024] = "";
  char cov_service[1024] = "";
  customvariablesmember *customvar = NULL;

  switch (event_type) {
  case NEBCALLBACK_HOST_CHECK_DATA:

    if ((host_chk_data = (nebstruct_host_check_data *) data)) {

      if (host_chk_data->type == NEBTYPE_HOSTCHECK_PROCESSED) {

        log_debug ("[alerta] Host check received.");

        host *host_object = host_chk_data->object_ptr;
        customvar = host_object->custom_variables;
        customvariablesmember *cvar;

        for (cvar = customvar; cvar != NULL; cvar = cvar->next) {
          if (!strcmp (cvar->variable_name, "ENVIRONMENT")) {
            sprintf (cov_environment, "%s", cvar->variable_value);
          }
          if (!strcmp (cvar->variable_name, "SERVICE")) {
            sprintf (cov_service, "%s", cvar->variable_value);
          }
        }

        sprintf (message,
                 "{"
                 "\"origin\":\"nagios/%s\","
                 "\"resource\":\"%s\","
                 "\"event\":\"%s\","
                 "\"group\":\"%s\","
                 "\"severity\":\"%s\","
                 "\"environment\":\"%s\","
                 "\"service\":[\"%s\"],"
                 "\"tags\":[\"check=%s\"],"
                 "\"text\":\"%s\","
                 "\"value\":\"%d/%d (%s)\","
                 "\"type\":\"nagiosHostAlert\","
                 "\"rawData\":\"%s\""
                 " }\n\r",
                 hostname, /* origin */
                 host_chk_data->host_name, /* resource */
                 "Host Check", /* event */
                 "Nagios", /* group */
                 display_state (host_chk_data->state), /* severity */
                 strcmp(cov_environment, "") ? cov_environment : environment, /* environment */
                 strcmp(cov_service, "") ? replace_char(cov_service, ',', "\",\"") : "Platform", /* service */
                 display_check_type (host_chk_data->check_type), /* tags */
                 host_chk_data->output, /* text */
                 host_chk_data->current_attempt, host_chk_data->max_attempts, display_state_type (host_chk_data->state_type), /* value */
                 host_chk_data->perf_data ? host_chk_data->perf_data : ""); /* rawData */

        downtime *dt;
        HASH_FIND_STR(downtimes, host_chk_data->host_name, dt);

        if (dt)
          log_debug ("[alerta] Host in downtime period -- suppress.");
        else
            if (hard_states_only && host_chk_data->state_type == SOFT_STATE)
              log_debug ("[alerta] Host in Soft state -- suppress.");
            else
              send_to_alerta (alert_url, message);
      }
    }

    break;

  case NEBCALLBACK_SERVICE_CHECK_DATA:

    if ((svc_chk_data = (nebstruct_service_check_data *) data)) {

      if (svc_chk_data->type == NEBTYPE_SERVICECHECK_PROCESSED) {

        if (!strcmp (svc_chk_data->service_description, "Heartbeat")) {

          if (svc_chk_data->return_code == STATE_OK) {
            log_debug ("[alerta] Heartbeat service check OK.");
            sprintf (message, "{ \"origin\": \"nagios/%s\", \"type\": \"Heartbeat\", \"tags\": [\"%s\"] }\n\r",
                     svc_chk_data->host_name, VERSION);

            send_to_alerta (heartbeat_url, message);
          }
          else {
            log_warning ("[alerta] Heartbeat service check failed.");
          }
        }
        else {

          log_debug ("[alerta] Service check received.");

          service *service_object = svc_chk_data->object_ptr;
          customvar = service_object->custom_variables;
          customvariablesmember *cvar;

          for (cvar = customvar; cvar != NULL; cvar = cvar->next) {
            if (!strcmp (cvar->variable_name, "ENVIRONMENT")) {
              sprintf (cov_environment, "%s", cvar->variable_value);
            }
            if (!strcmp (cvar->variable_name, "SERVICE")) {
              sprintf (cov_service, "%s", cvar->variable_value);
            }
          }

          sprintf (message,
                   "{"
                   "\"origin\":\"nagios/%s\","
                   "\"resource\":\"%s\","
                   "\"event\":\"%s\","
                   "\"group\":\"%s\","
                   "\"severity\":\"%s\","
                   "\"environment\":\"%s\","
                   "\"service\":[\"%s\"],"
                   "\"tags\":[\"check=%s\"],"
                   "\"text\":\"%s\","
                   "\"value\":\"%d/%d (%s)\","
                   "\"type\":\"nagiosServiceAlert\","
                   "\"rawData\":\"%s\""
                   "}\n\r",
                   hostname, /* origin */
                   svc_chk_data->host_name, /* resource */
                   svc_chk_data->service_description, /* event */
                   "Nagios", /* group */
                   display_state (svc_chk_data->state), /* severity */
                   strcmp(cov_environment, "") ? cov_environment : environment, /* environment */
                   strcmp(cov_service, "") ? replace_char(cov_service, ',', "\",\"") : "Platform", /* service */
                   display_check_type (svc_chk_data->check_type), /* tags */
                   svc_chk_data->output, /* text */
                   svc_chk_data->current_attempt, svc_chk_data->max_attempts, display_state_type (svc_chk_data->state_type), /* value */
                   svc_chk_data->perf_data ? svc_chk_data->perf_data : "");

          downtime *dt;
          char key[2048];
          sprintf(key, "%s~%s", svc_chk_data->host_name, svc_chk_data->service_description);
          HASH_FIND_STR(downtimes, key, dt);

          if (dt)
            log_debug ("[alerta] Service in downtime period -- suppress.");
          else
            if (hard_states_only && svc_chk_data->state_type == SOFT_STATE)
              log_debug ("[alerta] Service in Soft state -- suppress.");
            else
              send_to_alerta (alert_url, message);
        }
      }
    }

    break;

  case NEBCALLBACK_DOWNTIME_DATA:

    if ((downtime_data = (nebstruct_downtime_data *) data)) {

      char key[2048];
      downtime *dt = malloc(sizeof(downtime));
      if (downtime_data->downtime_type == HOST_DOWNTIME) {
        sprintf(key, "%s", downtime_data->host_name);
      } else if (downtime_data->downtime_type == SERVICE_DOWNTIME) {
        sprintf(key, "%s~%s", downtime_data->host_name, downtime_data->service_description);
      }
      strcpy(dt->key, key);
      dt->id = downtime_data->downtime_id;

      if (downtime_data->type == NEBTYPE_DOWNTIME_START) {

        log_debug ("[alerta] Downtime started.");

        HASH_ADD_STR(downtimes, key, dt);

        sprintf (message,
                 "{"
                 "\"origin\":\"nagios/%s\","
                 "\"resource\":\"%s\","
                 "\"event\":\"%s\","
                 "\"group\":\"%s\","
                 "\"severity\":\"%s\","
                 "\"environment\":\"%s\","
                 "\"service\":[\"%s\"],"
                 "\"tags\":[\"downtime=%s\"],"
                 "\"text\":\"DOWNTIME STARTED (%lus) - %s\","
                 "\"value\":\"id=%lu\","
                 "\"type\":\"%s\","
                 "\"rawData\":\"%s;%lu;%lu;%d;%lu;%lu;%s;%s\""
                 "}\n\r",
                 hostname, /* origin */
                 downtime_data->host_name, /* resource */
                 downtime_data->service_description ? downtime_data->service_description : "Host Check", /* event */
                 "Nagios", /* group */
                 "informational", /* severity */
                 strcmp(cov_environment, "") ? cov_environment : environment, /* environment */
                 strcmp(cov_service, "") ? replace_char(cov_service, ',', "\",\"") : "Platform", /* service */
                 display_downtime_type (downtime_data->downtime_type), /* tags */
                 downtime_data->duration, downtime_data->comment_data, /* text */
                 downtime_data->downtime_id, /* value */
                 downtime_data->downtime_type == HOST_DOWNTIME ? "nagiosHostAlert" : "nagiosServiceAlert",
                 downtime_data->host_name, downtime_data->start_time, downtime_data->end_time, downtime_data->fixed, downtime_data->triggered_by, downtime_data->duration, downtime_data->author_name, downtime_data->comment_data
                 );

        send_to_alerta (alert_url, message);
      }

      if (downtime_data->type == NEBTYPE_DOWNTIME_STOP) {

        log_debug ("[alerta] Downtime stopped.");

        downtime *dt;
        HASH_FIND_STR(downtimes, key, dt);
        if (dt) {
          HASH_DEL(downtimes, dt);
          free(dt);
        }

        sprintf (message,
                 "{"
                 "\"origin\":\"nagios/%s\","
                 "\"resource\":\"%s\","
                 "\"event\":\"%s\","
                 "\"group\":\"%s\","
                 "\"severity\":\"%s\","
                 "\"environment\":\"%s\","
                 "\"service\":[\"%s\"],"
                 "\"tags\":[\"downtime=%s\"],"
                 "\"text\":\"DOWNTIME %s - %s\","
                 "\"value\":\"id=%lu\","
                 "\"type\":\"%s\","
                 "\"rawData\":\"%s;%lu;%lu;%d;%lu;%lu;%s;%s\""
                 "}\n\r",
                 hostname, /* origin */
                 downtime_data->host_name, /* resource */
                 downtime_data->service_description ? downtime_data->service_description : "Host Check", /* event */
                 "Nagios", /* group */
                 "normal", /* severity */
                 strcmp(cov_environment, "") ? cov_environment : environment, /* environment */
                 strcmp(cov_service, "") ? replace_char(cov_service, ',', "\",\"") : "Platform", /* service */
                 display_downtime_type (downtime_data->downtime_type), /* tags */
                 downtime_data->attr == NEBATTR_DOWNTIME_STOP_CANCELLED ? "CANCELLED" : "STOPPED", downtime_data->comment_data, /* text */
                 downtime_data->downtime_id, /* value */
                 downtime_data->downtime_type == HOST_DOWNTIME ? "nagiosHostAlert" : "nagiosServiceAlert",
                 downtime_data->host_name, downtime_data->start_time, downtime_data->end_time, downtime_data->fixed, downtime_data->triggered_by, downtime_data->duration, downtime_data->author_name, downtime_data->comment_data
                 );

        send_to_alerta (alert_url, message);
      }
    }

    break;

  default:
    log_warning ("[alerta] ERROR: Callback triggered for unregistered event!");
    break;
  }

  return NEB_OK;
}
