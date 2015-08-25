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

#include <curl/curl.h>

NEB_API_VERSION (CURRENT_NEB_API_VERSION);

char *VERSION = "3.2.0";

void *alerta_module_handle = NULL;

int check_handler (int, void *);

int debug = 0;
char message[4096];
char hostname[1024];
char alert_url[1024];
char heartbeat_url[1024];
char auth_header[1024];
char environment[1024] = "Production";

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
replace_char(char *input_string, char old_char, char new_char)
{
  char *c = input_string;
  while(*c) {
    if(*c == old_char)
      *c = new_char;
    c++;
  }
  return input_string;
}

int
send_to_alerta(char *url, char *message)
{
  CURL *curl;
  CURLcode res;
  long status;

  curl = curl_easy_init ();

  if (!curl) {
    return NEB_ERROR;
  }

  char *message_mod = replace_char(message, '\\', ' ');  // avoid broken JSON output

  if (debug)
    write_to_all_logs (message, NSLOG_INFO_MESSAGE);

  struct curl_slist *headers = NULL;
  headers = curl_slist_append (headers, "Content-Type: application/json");
  if (strlen(auth_header))
    headers = curl_slist_append (headers, auth_header);
  curl_easy_setopt (curl, CURLOPT_URL, url);
  curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt (curl, CURLOPT_POSTFIELDS, message_mod);
  res = curl_easy_perform (curl);

  if (res != CURLE_OK) {
    sprintf (message, "[alerta] curl_easy_perform() failed: %s", curl_easy_strerror (res));
    write_to_all_logs (message, NSLOG_RUNTIME_ERROR);
    return res;
  }

  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
  sprintf (message, "[alerta] HTTP response status=%ld", status);
  if (status != 200)
    write_to_all_logs (message, NSLOG_RUNTIME_WARNING);
  else if (status == 200 && debug)
    write_to_all_logs (message, NSLOG_INFO_MESSAGE);

  curl_easy_cleanup (curl);
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
  neb_set_module_info (alerta_module_handle, NEBMODULE_MODINFO_COPYRIGHT, "Copyright (c) 2015 Nick Satterly");
  neb_set_module_info (alerta_module_handle, NEBMODULE_MODINFO_VERSION, VERSION);
  neb_set_module_info (alerta_module_handle, NEBMODULE_MODINFO_LICENSE, "MIT License");
  neb_set_module_info (alerta_module_handle, NEBMODULE_MODINFO_DESC,
                       "Nagios Event Broker module that forwards Nagios events to Alerta");

  write_to_all_logs ("[alerta] Initialising Nagios-Alerta Gateway module", NSLOG_INFO_MESSAGE);

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
  }
  if (strlen(endpoint)) {
    sprintf (alert_url, "%s/alert", endpoint);
    sprintf (heartbeat_url, "%s/heartbeat", endpoint);
    if (strlen(key))
      sprintf (auth_header, "Authorization: Key %s", key);
  } else {
    write_to_all_logs ("[alerta] API endpoint not configured", NSLOG_CONFIG_ERROR);
    exit(1);
  }

  if (debug)
    write_to_all_logs ("[alerta] debug is on", NSLOG_INFO_MESSAGE);

  curl_global_init (CURL_GLOBAL_ALL);

  neb_register_callback (NEBCALLBACK_HOST_CHECK_DATA, alerta_module_handle, 0, check_handler);
  neb_register_callback (NEBCALLBACK_SERVICE_CHECK_DATA, alerta_module_handle, 0, check_handler);
  neb_register_callback (NEBCALLBACK_DOWNTIME_DATA, alerta_module_handle, 0, check_handler);

  sprintf (message, "[alerta] Forward service and host checks and downtime to %s", endpoint);
  write_to_all_logs (message, NSLOG_INFO_MESSAGE);

  return NEB_OK;
}

int
nebmodule_deinit (int flags, int reason)
{
  curl_global_cleanup ();

  neb_deregister_callback (NEBCALLBACK_HOST_CHECK_DATA, check_handler);
  neb_deregister_callback (NEBCALLBACK_SERVICE_CHECK_DATA, check_handler);
  neb_deregister_callback (NEBCALLBACK_DOWNTIME_DATA, check_handler);

  write_to_all_logs ("NEB callbacks for host and service checks successfully de-registered. Bye.", NSLOG_INFO_MESSAGE);

  return NEB_OK;
}

int
check_handler (int event_type, void *data)
{
  nebstruct_host_check_data *host_chk_data = NULL;
  nebstruct_service_check_data *svc_chk_data = NULL;
  nebstruct_downtime_data *downtime_data = NULL;

  switch (event_type) {
  case NEBCALLBACK_HOST_CHECK_DATA:

    if ((host_chk_data = (nebstruct_host_check_data *) data)) {

      if (host_chk_data->type == NEBTYPE_HOSTCHECK_PROCESSED) {

        write_to_all_logs ("[alerta] Host check received.", NSLOG_INFO_MESSAGE);

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
                 environment,  /* environment */
                 "Platform", /* service */
                 display_check_type (host_chk_data->check_type), /* tags */
                 host_chk_data->output, /* text */
                 host_chk_data->current_attempt, host_chk_data->max_attempts, display_state_type (host_chk_data->state_type), /* value */
                 host_chk_data->perf_data ? host_chk_data->perf_data : ""); /* rawData */

        send_to_alerta (alert_url, message);
      }
    }

    break;

  case NEBCALLBACK_SERVICE_CHECK_DATA:

    if ((svc_chk_data = (nebstruct_service_check_data *) data)) {

      if (svc_chk_data->type == NEBTYPE_SERVICECHECK_PROCESSED) {

        if (!strcmp (svc_chk_data->service_description, "Heartbeat")) {

          if (svc_chk_data->return_code == STATE_OK) {
            write_to_all_logs ("[alerta] Heartbeat service check OK.", NSLOG_INFO_MESSAGE);
            sprintf (message, "{ \"origin\": \"nagios/%s\", \"type\": \"Heartbeat\", \"tags\": [\"%s\"] }\n\r",
                     svc_chk_data->host_name, VERSION);

            send_to_alerta (heartbeat_url, message);
          }
          else {
            write_to_all_logs ("[alerta] Heartbeat service check failed.", NSLOG_RUNTIME_WARNING);
          }

        }
        else {

          write_to_all_logs ("[alerta] Service check received.", NSLOG_INFO_MESSAGE);

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
                   environment,  /* environment */
                   "Platform", /* service */
                   display_check_type (svc_chk_data->check_type), /* tags */
                   svc_chk_data->output, /* text */
                   svc_chk_data->current_attempt, svc_chk_data->max_attempts, display_state_type (svc_chk_data->state_type), /* value */
                   svc_chk_data->perf_data ? svc_chk_data->perf_data : "");

          send_to_alerta (alert_url, message);
        }
      }
    }

    break;

  case NEBCALLBACK_DOWNTIME_DATA:

    if ((downtime_data = (nebstruct_downtime_data *) data)) {

      if (downtime_data->type == NEBTYPE_DOWNTIME_START) {

        write_to_all_logs ("[alerta] Downtime started.", NSLOG_INFO_MESSAGE);

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
                 environment, /* environment */
                 "Platform", /* service */
                 display_downtime_type (downtime_data->downtime_type), /* tags */
                 downtime_data->duration, downtime_data->comment_data, /* text */
                 downtime_data->downtime_id, /* value */
                 downtime_data->downtime_type == HOST_DOWNTIME ? "nagiosHostAlert" : "nagiosServiceAlert",
                 downtime_data->host_name, downtime_data->start_time, downtime_data->end_time, downtime_data->fixed, downtime_data->triggered_by, downtime_data->duration, downtime_data->author_name, downtime_data->comment_data
                 );

        send_to_alerta (alert_url, message);
      }

      if (downtime_data->type == NEBTYPE_DOWNTIME_STOP) {

        write_to_all_logs ("[alerta] Downtime stopped.", NSLOG_INFO_MESSAGE);

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
                 environment, /* environment */
                 "Platform", /* service */
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
    write_to_all_logs ("[alerta] ERROR: Callback triggered for unregistered event!", NSLOG_RUNTIME_WARNING);
    break;
  }

  return NEB_OK;
}
