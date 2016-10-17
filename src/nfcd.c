/*
 * NFC Event Daemon
 * Generate events on tag status change
 * Copyright (C) 2009 Romuald Conty <romuald@libnfc.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif // HAVE_CONFIG_H

#include <nfc/nfc.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include <unistd.h>

#include <errno.h>
#include <signal.h>

#include "types.h"

/**
 * @macro DBG
 * @brief Print a message of standard output only in DEBUG mode
 */
#ifdef DEBUG
#  define DBG(...) do { \
    printf ("DBG %s:%d", __FILE__, __LINE__); \
    printf ("    " __VA_ARGS__ ); \
} while (0)
#else
#  define DBG(...) {}
#endif

#define DEF_POLLING 1    /* 1 second timeout */
#define DEF_EXPIRE 0    /* no expire */

#define DEF_CONFIG_FILE SYSCONFDIR"/nfc-eventd.conf"

int polling_time;
int expire_time;
int daemonize = 0;
int debug;
char *cfgfile;

nfc_device* device = NULL;
nfc_context* context;

bool quit_flag = false;

static void stop_polling(int sig)
{
  (void) sig;
  DBG( "Stop polling... (sig:%d)", sig);
  if (device != NULL) {
    nfc_abort_command(device);
    DBG( "%s", "Polling aborted.");
    quit_flag = true;
  } else {
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
}


/**
 * @brief Execute NEM function that handle events
 */
static int execute_event ( const nfc_device *dev, const nfc_target* tag, const nem_event_t event ) {
    return printf("%s\n", __FUNCTION__);
}


typedef enum {
  NFC_POLL_HARDWARE,
  NFC_POLL_SOFTWARE,
} nfc_poll_mode;

static nfc_target*
ned_poll_for_tag(nfc_device* dev, nfc_target* tag)
{
  uint8_t uiPollNr;
  const uint8_t uiPeriod = 2; /* 2 x 150 ms = 300 ms */
  const nfc_modulation nm[1] = { { .nmt = NMT_ISO14443A, .nbr = NBR_106 } };

  if( tag != NULL ) {
    /* We are looking for a previous tag */
    /* In this case, to prevent for intensive polling we add a sleeping time */
    sleep ( polling_time );
    uiPollNr = 3; /* Polling duration : btPollNr * szTargetTypes * btPeriod * 150 = btPollNr * 300 = 900 */
  } else {
    /* We are looking for any tag */
    uiPollNr = 0xff; /* We endless poll for a new tag */
  }

  nfc_target target;
  int res = nfc_initiator_poll_target (dev, nm, 1, uiPollNr, uiPeriod, &target);
  if (res > 0) {
    if ( (tag != NULL) && (0 == memcmp(tag->nti.nai.abtUid, target.nti.nai.abtUid, target.nti.nai.szUidLen)) ) {
      return tag;
    } else {
      nfc_target* rv = malloc(sizeof(nfc_target));
      memcpy(rv, &target, sizeof(nfc_target));
      nfc_initiator_deselect_target ( dev );
      return rv;
    }
  } else {
    return NULL;
  }
}

int
main ( int argc, char *argv[] ) {
    nfc_target* old_tag = NULL;
    nfc_target* new_tag;

    int expire_count = 0;

    /* put my self into background if flag is set */
    if ( daemonize ) {
        DBG ( "%s", "Going to be daemon..." );
        if ( daemon ( 0, debug ) < 0 ) {
            printf ( "Error in daemon() call: %s", strerror ( errno ) );
            return 1;
        }
    }

    /*
     * Wait endlessly for all events in the list of readers
     * We only stop in case of an error
     *
     * COMMENT:
     * There are no way in libnfc API to detect if a card is present or not
     * so the way we proceed is to look for an tag
     * Any ideas will be welcomed
     */
    signal(SIGINT, stop_polling);
    signal(SIGTERM, stop_polling);

    nfc_init(&context);
    if (context == NULL) {
      printf("Unable to init libnfc (malloc)");
      exit(EXIT_FAILURE);
    }
    // Try to open the NFC device
    if ( device == NULL ) device = nfc_open( context, NULL );
    if ( device == NULL ) {
        printf( "%s", "NFC device not found" );
        exit(EXIT_FAILURE);
    }
    nfc_initiator_init ( device );

    // Drop the field for a while
    nfc_device_set_property_bool ( device, NP_ACTIVATE_FIELD, false );
    nfc_device_set_property_bool ( device, NP_INFINITE_SELECT, false );

    // Configure the CRC and Parity settings
    nfc_device_set_property_bool ( device, NP_HANDLE_CRC, true );
    nfc_device_set_property_bool ( device, NP_HANDLE_PARITY, true );

    // Enable field so more power consuming cards can power themselves up
    nfc_device_set_property_bool ( device, NP_ACTIVATE_FIELD, true );

    printf( "Connected to NFC device: %s", nfc_device_get_name(device) );

    do {
detect:
        new_tag = ned_poll_for_tag(device, old_tag);

        if ( old_tag == new_tag ) { /* state unchanged */
            /* on card not present, increase and check expire time */
            if (( !quit_flag ) && ( expire_time == 0 )) goto detect;
            if (( !quit_flag ) && ( new_tag != NULL )) goto detect;
            expire_count += polling_time;
            if ( expire_count >= expire_time ) {
                DBG ( "%s", "Timeout on tag removed " );
                execute_event ( device, new_tag,EVENT_EXPIRE_TIME );
                expire_count = 0; /*restart timer */
            }
        } else { /* state changed; parse event */
            expire_count = 0;
            if ( new_tag == NULL ) {
                DBG ( "%s", "Event detected: tag removed" );
                execute_event ( device, old_tag, EVENT_TAG_REMOVED );
                free(old_tag);
            } else {
                DBG ( "%s", "Event detected: tag inserted " );
                execute_event ( device, new_tag, EVENT_TAG_INSERTED );
            }
            old_tag = new_tag;
        }
    } while ( !quit_flag );

    if ( device != NULL ) {
        nfc_close(device);
        DBG ( "NFC device (0x%08x) is disconnected", device );
        device = NULL;
    }

    /* If we get here means that an error or exit status occurred */
    DBG ( "%s", "Exited from main loop" );
    nfc_exit(context);
    exit ( EXIT_FAILURE );
} /* main */

