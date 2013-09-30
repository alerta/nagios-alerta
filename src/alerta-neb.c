/*****************************************************************************
 *
 * ALERTA-NEB.C
 *
 *     $ indent -br -nut -l125 alerta-neb.c
 *
 *****************************************************************************/

#include "../include/config.h"

#include "../include/nebmodules.h"
#include "../include/nebcallbacks.h"

#include "../include/nebstructs.h"
#include "../include/neberrors.h"
#include "../include/broker.h"

#include "../include/config.h"
#include "../include/common.h"
#include "../include/nagios.h"

#include <curl/curl.h>

NEB_API_VERSION (CURRENT_NEB_API_VERSION);

char *VERSION = "0.1";

void *alerta_module_handle = NULL;

int check_handler (int, void *);

int debug = 0;
char message[4096];
char hostname[1024];
char alert_url[1024];
char heartbeat_url[1024];

CURL *curl;
CURLcode res;

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

int
nebmodule_init (int flags, char *args, nebmodule * handle)
{
  time_t clock;
  unsigned long interval;
  gethostname (hostname, 1023);

  alerta_module_handle = handle;        /* save the neb module handle */

  neb_set_module_info (alerta_module_handle, NEBMODULE_MODINFO_TITLE, "Nagios-Alerta Gateway");
  neb_set_module_info (alerta_module_handle, NEBMODULE_MODINFO_AUTHOR, "Nick Satterly");
  neb_set_module_info (alerta_module_handle, NEBMODULE_MODINFO_COPYRIGHT, "Copyright (c) 2013 Nick Satterly");
  neb_set_module_info (alerta_module_handle, NEBMODULE_MODINFO_VERSION, VERSION);
  neb_set_module_info (alerta_module_handle, NEBMODULE_MODINFO_LICENSE, "MIT License");
  neb_set_module_info (alerta_module_handle, NEBMODULE_MODINFO_DESC,
                       "Nagios Event Broker module that forwards Nagios events to Alerta");

  write_to_all_logs ("[alerta] Initialising Nagios-Alerta Gateway module", NSLOG_INFO_MESSAGE);

  char endpoint[1024];
  char *token;
  while ((token = strsep (&args, " ")) != NULL) {
    if (strncasecmp (token, "http://", 7) == 0)
      strcpy (endpoint, token);
    if (strncasecmp (token, "debug=1", 7) == 0)
      debug = 1;
  }
  sprintf (alert_url, "%s/alerta/api/v2/alerts/alert.json", endpoint);
  sprintf (heartbeat_url, "%s/alerta/api/v2/heartbeats/heartbeat.json", endpoint);

  if (debug)
    write_to_all_logs ("[alerta] debug is on", NSLOG_INFO_MESSAGE);

  curl_global_init (CURL_GLOBAL_ALL);

  neb_register_callback (NEBCALLBACK_HOST_CHECK_DATA, alerta_module_handle, 0, check_handler);
  neb_register_callback (NEBCALLBACK_SERVICE_CHECK_DATA, alerta_module_handle, 0, check_handler);

  sprintf (message, "[alerta] Forward service and host checks to %s", alert_url);
  write_to_all_logs (message, NSLOG_INFO_MESSAGE);

  return NEB_OK;
}

int
nebmodule_deinit (int flags, int reason)
{
  curl_global_cleanup ();

  neb_deregister_callback (NEBCALLBACK_HOST_CHECK_DATA, check_handler);
  neb_deregister_callback (NEBCALLBACK_SERVICE_CHECK_DATA, check_handler);

  write_to_all_logs ("NEB callbacks for host and service checks successfully de-registered. Bye.", NSLOG_INFO_MESSAGE);

  return NEB_OK;
}

int
check_handler (int event_type, void *data)
{
  nebstruct_host_check_data *host_chk_data = NULL;
  nebstruct_service_check_data *svc_chk_data = NULL;

  curl = curl_easy_init ();

  if (!curl) {
    return NEB_ERROR;
  }

  switch (event_type) {
  case NEBCALLBACK_HOST_CHECK_DATA:

    if ((host_chk_data = (nebstruct_host_check_data *) data)) {

      if (host_chk_data->type == NEBTYPE_HOSTCHECK_PROCESSED) {

        write_to_all_logs ("[alerta] Host check received.", NSLOG_INFO_MESSAGE);

        sprintf (message,
                 "{ \"origin\": \"nagios3/%s\", \"resource\": \"%s\", \"event\": \"%s\", \"group\": \"%s\", \"severity\": \"%s\", \"environment\": [ \"%s\" ], \"service\": [ \"%s\" ], \"tags\": [ \"%s\" ], \"text\": \"%s\", \"value\": \"%d/%d (%s)\", \"type\": \"nagiosHostAlert\", \"rawData\": \"%s\" }\n\r",
                 hostname, host_chk_data->host_name, "Host Check", "Nagios", display_state (host_chk_data->state), "INFRA",
                 "Common", display_check_type (host_chk_data->check_type), host_chk_data->output,
                 host_chk_data->current_attempt, host_chk_data->max_attempts, display_state_type (host_chk_data->state_type),
                 host_chk_data->perf_data ? host_chk_data->perf_data : "");

        if (debug)
          write_to_all_logs (message, NSLOG_INFO_MESSAGE);

        struct curl_slist *headers = NULL;
        headers = curl_slist_append (headers, "Content-Type: application/json");
        curl_easy_setopt (curl, CURLOPT_URL, alert_url);
        curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt (curl, CURLOPT_POSTFIELDS, message);
        res = curl_easy_perform (curl);

        if (res != CURLE_OK) {
          sprintf (message, "[alerta] curl_easy_perform() failed: %s", curl_easy_strerror (res));
          write_to_all_logs (message, NSLOG_RUNTIME_ERROR);
        }

        curl_easy_cleanup (curl);
      }
    }

    break;

  case NEBCALLBACK_SERVICE_CHECK_DATA:

    if ((svc_chk_data = (nebstruct_service_check_data *) data)) {

      if (svc_chk_data->type == NEBTYPE_SERVICECHECK_PROCESSED) {

        if (!strcmp (svc_chk_data->service_description, "Heartbeat")) {

          if (svc_chk_data->return_code == STATE_OK) {
            write_to_all_logs ("[alerta] Heartbeat service check OK.", NSLOG_INFO_MESSAGE);
            sprintf (message, "{ \"origin\": \"nagios3/%s\", \"type\": \"Heartbeat\", \"version\": \"%s\" }\n\r",
                     svc_chk_data->host_name, VERSION);

            if (debug)
              write_to_all_logs (message, NSLOG_INFO_MESSAGE);

            struct curl_slist *headers = NULL;
            headers = curl_slist_append (headers, "Content-Type: application/json");
            curl_easy_setopt (curl, CURLOPT_URL, heartbeat_url);
            curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt (curl, CURLOPT_POSTFIELDS, message);
            res = curl_easy_perform (curl);

            if (res != CURLE_OK) {
              sprintf (message, "[alerta] curl_easy_perform() failed: %s", curl_easy_strerror (res));
              write_to_all_logs (message, NSLOG_RUNTIME_ERROR);
            }

            curl_easy_cleanup (curl);

          }
          else {
            write_to_all_logs ("[alerta] Heartbeat service check failed.", NSLOG_RUNTIME_WARNING);
          }

        }
        else {

          write_to_all_logs ("[alerta] Service check received.", NSLOG_INFO_MESSAGE);

          sprintf (message,
                   "{ \"origin\": \"nagios3/%s\", \"resource\": \"%s\", \"event\": \"%s\", \"group\": \"%s\", \"severity\": \"%s\", \"environment\": [ \"%s\" ], \"service\": [ \"%s\" ], \"tags\": [ \"%s\" ], \"text\": \"%s\", \"value\": \"%d/%d (%s)\", \"type\": \"nagioServiceAlert\", \"rawData\": \"%s\" }\n\r",
                   hostname, svc_chk_data->host_name, svc_chk_data->service_description, "Nagios",
                   display_state (svc_chk_data->state), "INFRA", "Common", display_check_type (svc_chk_data->check_type),
                   svc_chk_data->output, svc_chk_data->current_attempt, svc_chk_data->max_attempts,
                   display_state_type (svc_chk_data->state_type), svc_chk_data->perf_data ? svc_chk_data->perf_data : "");

          if (debug)
            write_to_all_logs (message, NSLOG_INFO_MESSAGE);

          struct curl_slist *headers = NULL;
          headers = curl_slist_append (headers, "Content-Type: application/json");
          curl_easy_setopt (curl, CURLOPT_URL, alert_url);
          curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers);
          curl_easy_setopt (curl, CURLOPT_POSTFIELDS, message);
          res = curl_easy_perform (curl);

          if (res != CURLE_OK) {
            sprintf (message, "[alerta] curl_easy_perform() failed: %s", curl_easy_strerror (res));
            write_to_all_logs (message, NSLOG_RUNTIME_ERROR);
          }

          curl_easy_cleanup (curl);
        }
      }
    }

    break;

  default:
    write_to_all_logs ("[alerta] ERROR: Callback triggered for unregistered event!", NSLOG_RUNTIME_WARNING);
    break;
  }

  return NEB_OK;
}
