
#ifndef nagios_h
#define nagios_h

#define NSCORE

#ifdef NAGIOS3
#include "nagios3/nebmodules.h"
#include "nagios3/nebcallbacks.h"
#include "nagios3/nebstructs.h"
#include "nagios3/neberrors.h"
#include "nagios3/broker.h"
#include "nagios3/logging.h"
#include "nagios3/config.h"
#include "nagios3/common.h"
#include "nagios3/nagios.h"
#endif  // NAGIOS3

#ifdef NAGIOS4
#include "nagios4/nebmodules.h"
#include "nagios4/nebcallbacks.h"
#include "nagios4/nebstructs.h"
#include "nagios4/neberrors.h"
#include "nagios4/broker.h"
#include "nagios4/logging.h"
#include "nagios4/config.h"
#include "nagios4/common.h"
#include "nagios4/nagios.h"
#endif  // NAGIOS4

#ifdef NAEMON
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include <naemon/naemon.h>
#endif  // NAEMON

#endif  // nagios_h
