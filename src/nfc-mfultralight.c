/*-
 * Free/Libre Near Field Communication (NFC) library
 *
 * Libnfc historical contributors:
 * Copyright (C) 2009      Roel Verdult
 * Copyright (C) 2009-2013 Romuald Conty
 * Copyright (C) 2010-2012 Romain Tartière
 * Copyright (C) 2010-2013 Philippe Teuwen
 * Copyright (C) 2012-2013 Ludovic Rousseau
 * See AUTHORS file for a more comprehensive list of contributors.
 * Additional contributors of this file:
 * Copyright (C) 2013      Adam Laurie
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  1) Redistributions of source code must retain the above copyright notice,
 *  this list of conditions and the following disclaimer.
 *  2 )Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Note that this license only applies on the examples, NFC library itself is under LGPL
 *
 */

/**
 * @file nfc-mfultralight.c
 * @brief MIFARE Ultralight dump/restore tool
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif // HAVE_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <string.h>
#include <ctype.h>

#include <nfc/nfc.h>

#include "nfc-utils.h"
#include "mifare.h"

#define MAX_TARGET_COUNT 16
#define MAX_UID_LEN 10
#define BLOCK_COUNT 0xf

#if 0
static nfc_device *pnd;
static nfc_target nt;
static mifare_param mp;
static mifareul_tag mtDump;
static const uint32_t uiBlocks = BLOCK_COUNT;

// special unlock command
uint8_t  abtUnlock1[1] = { 0x40 };
uint8_t  abtUnlock2[1] = { 0x43 };

//Halt command
uint8_t  abtHalt[4] = { 0x50, 0x00, 0x00, 0x00 };

#define MAX_FRAME_LEN 264

static uint8_t abtRx[MAX_FRAME_LEN];
static int szRxBits;
#endif

static const nfc_modulation nmMifare = {
  .nmt = NMT_ISO14443A,
  .nbr = NBR_106,
};

static void
print_success_or_failure(bool bFailure, uint32_t *uiCounter)
{
  printf("%c", (bFailure) ? 'x' : '.');
  if (uiCounter)
    *uiCounter += (bFailure) ? 0 : 1;
}

bool
mifare_ultralight_read_card(nfc_device *pnd, nfc_target *pnt, mifare_param *pmp, mifareul_tag *ptag)
{
  mifare_param mp;
  uint32_t page;
  bool    bFailure = false;
  uint32_t uiReadedPages = 0;
  const uint32_t uiBlocks = BLOCK_COUNT;

  printf("Reading %d pages |", uiBlocks + 1);

  for (page = 0; page <= uiBlocks; page += 4) {
    // Try to read out the data block
    if (nfc_initiator_mifare_cmd(pnd, MC_READ, page, &mp)) {
      memcpy(ptag->amb[page / 4].mbd.abtData, mp.mpd.abtData, 16);
    } else {
      bFailure = true;
      break;
    }

    print_success_or_failure(bFailure, &uiReadedPages);
    print_success_or_failure(bFailure, &uiReadedPages);
    print_success_or_failure(bFailure, &uiReadedPages);
    print_success_or_failure(bFailure, &uiReadedPages);
  }
  printf("|\n");
  printf("Done, %d of %d pages read.\n", uiReadedPages, uiBlocks + 1);
  fflush(stdout);

  return (!bFailure);
}


#if 0
int
_main(int argc, const char *argv[])
{
  int     iAction = 0;
  uint8_t iUID[MAX_UID_LEN] = { 0x0 };
  size_t  szUID = 0;
  bool    bOTP = false;
  bool    bLock = false;
  bool    bUID = false;
  FILE   *pfDump;

  if (argc < 2) {
      print_usage(argv);
      exit(EXIT_FAILURE);
  }

  DBG("\nChecking arguments and settings\n");

  // Get commandline options
  for (int arg = 1; arg < argc; arg++) {
    if (0 == strcmp(argv[arg], "r")) {
      iAction = 1;
    } else if (0 == strcmp(argv[arg], "w")) {
      iAction = 2;
    } else if (0 == strcmp(argv[arg], "--with-uid")) {
      if (argc < 5) {
        ERR("Please supply a UID of 4, 7 or 10 bytes long. Ex: a1:b2:c3:d4");
        exit(EXIT_FAILURE);
      }
      szUID = str_to_uid(argv[4], iUID);
    } else if (0 == strcmp(argv[arg], "--full")) {
      bOTP = true;
      bLock = true;
      bUID = true;
    } else if (0 == strcmp(argv[arg], "--otp")) {
      bOTP = true;
    } else if (0 == strcmp(argv[arg], "--lock")) {
      bLock = true;
    } else if (0 == strcmp(argv[arg], "--uid")) {
      bUID = true;
    } else if (0 == strcmp(argv[arg], "--check-magic")) {
      iAction = 3;
    } else {
      //Skip validation of the filename
      if ((arg != 2) && (arg != 4)) {
        ERR("%s is not supported option.", argv[arg]);
        print_usage(argv);
        exit(EXIT_FAILURE);
      }
    }
  }

  if (iAction == 1) {
    memset(&mtDump, 0x00, sizeof(mtDump));
  } else if (iAction == 2) {
    pfDump = fopen(argv[2], "rb");

    if (pfDump == NULL) {
      ERR("Could not open dump file: %s\n", argv[2]);
      exit(EXIT_FAILURE);
    }

    if (fread(&mtDump, 1, sizeof(mtDump), pfDump) != sizeof(mtDump)) {
      ERR("Could not read from dump file: %s\n", argv[2]);
      fclose(pfDump);
      exit(EXIT_FAILURE);
    }
    fclose(pfDump);
    DBG("Successfully opened the dump file\n");
  } else if (iAction == 3) {
    DBG("Switching to Check Magic Mode\n");
  } else {
    ERR("Unable to determine operating mode");
    exit(EXIT_FAILURE);
  }

  nfc_context *context;
  nfc_init(&context);
  if (context == NULL) {
    ERR("Unable to init libnfc (malloc)");
    exit(EXIT_FAILURE);
  }

  // Try to open the NFC device
  pnd = nfc_open(context, NULL);
  if (pnd == NULL) {
    ERR("Error opening NFC device");
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  printf("NFC device: %s opened\n", nfc_device_get_name(pnd));

  if (list_passive_targets(pnd)) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  if (nfc_initiator_init(pnd) < 0) {
    nfc_perror(pnd, "nfc_initiator_init");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  // Let the device only try once to find a tag
  if (nfc_device_set_property_bool(pnd, NP_INFINITE_SELECT, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  // Try to find a MIFARE Ultralight tag
  if (nfc_initiator_select_passive_target(pnd, nmMifare, (szUID) ? iUID : NULL, szUID, &nt) <= 0) {
    ERR("no tag was found\n");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  // Test if we are dealing with a MIFARE compatible tag

  if (nt.nti.nai.abtAtqa[1] != 0x44) {
    ERR("tag is not a MIFARE Ultralight card\n");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  // Get the info from the current tag
  printf("Using MIFARE Ultralight card with UID: ");
  size_t  szPos;
  for (szPos = 0; szPos < nt.nti.nai.szUidLen; szPos++) {
    printf("%02x", nt.nti.nai.abtUid[szPos]);
  }
  printf("\n");

  if (iAction == 1) {
    if (read_card()) {
      printf("Writing data to file: %s ... ", argv[2]);
      fflush(stdout);
      pfDump = fopen(argv[2], "wb");
      if (pfDump == NULL) {
        printf("Could not open file: %s\n", argv[2]);
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
      }
      if (fwrite(&mtDump, 1, sizeof(mtDump), pfDump) != sizeof(mtDump)) {
        printf("Could not write to file: %s\n", argv[2]);
        fclose(pfDump);
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
      }
      fclose(pfDump);
      printf("Done.\n");
    }
  } else if (iAction == 2) {
    write_card(bOTP, bLock, bUID);
  } else if (iAction == 3) {
    if (!check_magic()) {
        printf("Card is not magic\n");
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    } else {
        printf("Card is magic\n");
    }
  }

  nfc_close(pnd);
  nfc_exit(context);
  exit(EXIT_SUCCESS);
}
#endif
