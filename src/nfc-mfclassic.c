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
 * Copyright (C) 2011-2013 Adam Laurie
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
 * @file nfc-mfclassic.c
 * @brief MIFARE Classic manipulation example
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

#include "mifare.h"
#include "nfc-utils.h"

#if 0
static nfc_context *context;
static nfc_device *pnd;
static nfc_target nt;
static mifare_param mp;
static mifare_classic_tag mtKeys;
static mifare_classic_tag mtDump;
static bool bUseKeyA;
static bool bUseKeyFile;
static bool bForceKeyFile;
static bool bTolerateFailures;
static bool bFormatCard;
static bool magic2 = false;
static uint8_t uiBlocks;
#endif
static uint8_t keys[] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7,
  0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
  0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
  0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd,
  0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a,
  0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xab, 0xcd, 0xef, 0x12, 0x34, 0x56
};

static const nfc_modulation nmMifare = {
  .nmt = NMT_ISO14443A,
  .nbr = NBR_106,
};

static size_t num_keys = sizeof(keys) / 6;

#define MAX_FRAME_LEN 264

static uint8_t abtRx[MAX_FRAME_LEN];

uint8_t  abtHalt[4] = { 0x50, 0x00, 0x00, 0x00 };

// special unlock command
uint8_t  abtUnlock1[1] = { 0x40 };
uint8_t  abtUnlock2[1] = { 0x43 };


static void
print_success_or_failure(bool bFailure, uint32_t *uiBlockCounter)
{
  printf("%c", (bFailure) ? 'x' : '.');
  if (uiBlockCounter && !bFailure)
    *uiBlockCounter += 1;
}

static  bool
is_first_block(uint32_t uiBlock)
{
  // Test if we are in the small or big sectors
  if (uiBlock < 128)
    return ((uiBlock) % 4 == 0);
  else
    return ((uiBlock) % 16 == 0);
}

static  bool
is_trailer_block(uint32_t uiBlock)
{
  // Test if we are in the small or big sectors
  if (uiBlock < 128)
    return ((uiBlock + 1) % 4 == 0);
  else
    return ((uiBlock + 1) % 16 == 0);
}

static  uint32_t
get_trailer_block(uint32_t uiFirstBlock)
{
  // Test if we are in the small or big sectors
  uint32_t trailer_block = 0;
  if (uiFirstBlock < 128) {
    trailer_block = uiFirstBlock + (3 - (uiFirstBlock % 4));
  } else {
    trailer_block = uiFirstBlock + (15 - (uiFirstBlock % 16));
  }
  return trailer_block;
}

static  bool
authenticate(nfc_device *pnd, nfc_target *pnt, bool bUseKeyA, uint32_t uiBlock, mifare_param *pmp)
{
  mifare_cmd mc;
  mifare_param mp;

  // Set the authentication information (uid)
  memcpy(mp.mpa.abtAuthUid, pnt->nti.nai.abtUid + pnt->nti.nai.szUidLen - 4, 4);

  // Should we use key A or B?
  mc = (bUseKeyA) ? MC_AUTH_A : MC_AUTH_B;

  if (pmp) {
    memcpy(mp.mpa.abtKey, pmp->mpa.abtKey, 6);
    if (nfc_initiator_select_passive_target(pnd, nmMifare, pnt->nti.nai.abtUid, pnt->nti.nai.szUidLen, NULL) <= 0) {
      ERR("tag was removed");
      return false;
    }
  } else {
    // If no key specifying, try to guess the right key
    for (size_t key_index = 0; key_index < num_keys; key_index++) {
      memcpy(mp.mpa.abtKey, keys + (key_index * 6), 6);
      if (nfc_initiator_mifare_cmd(pnd, mc, uiBlock, &mp)) {
        return true;
      }
      if (nfc_initiator_select_passive_target(pnd, nmMifare, pnt->nti.nai.abtUid, pnt->nti.nai.szUidLen, NULL) <= 0) {
        ERR("tag was removed");
        return false;
      }
    }
  }

  return false;
}


static int
get_rats(nfc_device *pnd, nfc_target *pnt)
{
  int res;
  uint8_t  abtRats[2] = { 0xe0, 0x50};
  // Use raw send/receive methods
  if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, false) < 0) {
    nfc_perror(pnd, "nfc_configure");
    return -1;
  }
  res = nfc_initiator_transceive_bytes(pnd, abtRats, sizeof(abtRats), abtRx, sizeof(abtRx), 0);
  if (res > 0) {
    // ISO14443-4 card, turn RF field off/on to access ISO14443-3 again
    if (nfc_device_set_property_bool(pnd, NP_ACTIVATE_FIELD, false) < 0) {
      nfc_perror(pnd, "nfc_configure");
      return -1;
    }
    if (nfc_device_set_property_bool(pnd, NP_ACTIVATE_FIELD, true) < 0) {
      nfc_perror(pnd, "nfc_configure");
      return -1;
    }
  }
#if 0
  // Reselect tag
  if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, pnt) <= 0) {
    printf("Error: tag disappeared\n");
    return -1;
  }
#endif
  return res;
}

static int
get_uiblocks(nfc_device *pnd, nfc_target *pnt)
{
  uint8_t uiblocks;

  // Guessing size
  if ((pnt->nti.nai.abtAtqa[1] & 0x02) == 0x02)
    // 4K
    uiblocks = 0xff;
  else if ((pnt->nti.nai.btSak & 0x01) == 0x01)
    // 320b
    uiblocks = 0x13;
  else
    // 1K/2K, checked through RATS
    uiblocks = 0x3f;

  // Testing RATS
  int res;
  if ((res = get_rats(pnd, pnt)) > 0) {
    if ((res >= 10) && (abtRx[5] == 0xc1) && (abtRx[6] == 0x05)
        && (abtRx[7] == 0x2f) && (abtRx[8] == 0x2f)
        && ((pnt->nti.nai.abtAtqa[1] & 0x02) == 0x00)) {
      // MIFARE Plus 2K
      uiblocks = 0x7f;
    }
  }

  return uiblocks;
}

bool
mifare_classic_read_card(nfc_device *pnd, nfc_target *pnt, bool bUseKeyA, mifare_param *pmp, mifare_classic_tag *ptag)
{
  mifare_param mp;
  int32_t iBlock;
  bool    bFailure = false;
  uint32_t uiReadBlocks = 0;
  uint8_t uiBlocks = get_uiblocks(pnd, pnt);


  printf("Reading out %d blocks |", uiBlocks + 1);
  // Read the card from end to begin
  for (iBlock = uiBlocks; iBlock >= 0; iBlock--) {
    // Authenticate everytime we reach a trailer block
    if (is_trailer_block(iBlock)) {
      if (bFailure) {
        // When a failure occured we need to redo the anti-collision
        if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, pnt) <= 0) {
          printf("!\nError: tag was removed\n");
          return false;
        }
        bFailure = false;
      }

      fflush(stdout);

      // Try to authenticate for the current sector
      if (!authenticate(pnd, pnt, bUseKeyA, iBlock, pmp)) {
        printf("!\nError: authentication failed for block 0x%02x\n", iBlock);
        return false;
      }
      // Try to read out the trailer
      if (!nfc_initiator_mifare_cmd(pnd, MC_READ, iBlock, &mp)) {
        printf("!\nfailed to read trailer block 0x%02x\n", iBlock);
        bFailure = true;
      }
    } else {
      // Make sure a earlier readout did not fail
      if (!bFailure) {
        // Try to read out the data block
        if (nfc_initiator_mifare_cmd(pnd, MC_READ, iBlock, &mp)) {
          memcpy(ptag->amb[iBlock].mbd.abtData, mp.mpd.abtData, 16);
        } else {
          printf("!\nError: unable to read block 0x%02x\n", iBlock);
          bFailure = true;
        }
      }
    }
    // Show if the readout went well for each block
    print_success_or_failure(bFailure, &uiReadBlocks);
    if (bFailure)
      return false;
  }
  printf("|\n");
  printf("Done, %d of %d blocks read.\n", uiReadBlocks, uiBlocks + 1);
  fflush(stdout);

  return true;
}

bool
mifare_classic_write_card(nfc_device *pnd, nfc_target *pnt, bool bUseKeyA, mifare_param *pmp, mifare_classic_tag *ptag)
{
  mifare_param mp;
  uint32_t uiBlock;
  bool    bFailure = false;
  uint32_t uiWriteBlocks = 0;
  uint8_t uiBlocks = get_uiblocks(pnd, pnt);

  printf("Writing %d blocks |", uiBlocks + 1);
  // Write the card from begin to end;
  for (uiBlock = 0; uiBlock <= uiBlocks; uiBlock++) {
    // Authenticate everytime we reach the first sector of a new block
    if (is_first_block(uiBlock)) {
      if (bFailure) {
        // When a failure occured we need to redo the anti-collision
        if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, pnt) <= 0) {
          printf("!\nError: tag was removed\n");
          return false;
        }
        bFailure = false;
      }

      fflush(stdout);

      // Try to authenticate for the current sector
      if (!authenticate(pnd, pnt, bUseKeyA, uiBlock, pmp)) {
        printf("!\nError: authentication failed for block %02x\n", uiBlock);
        return false;
      }
    }

    if (is_trailer_block(uiBlock)) {
      // Copy the keys over from our key dump and store the retrieved access bits
      memcpy(mp.mpd.abtData,      ptag->amb[uiBlock].mbt.abtKeyA, 6);
      memcpy(mp.mpd.abtData + 6,  ptag->amb[uiBlock].mbt.abtAccessBits, 4);
      memcpy(mp.mpd.abtData + 10, ptag->amb[uiBlock].mbt.abtKeyB, 6);

      // Try to write the trailer
      if (nfc_initiator_mifare_cmd(pnd, MC_WRITE, uiBlock, &mp) == false) {
        printf("failed to write trailer block %d \n", uiBlock);
        bFailure = true;
      }
    } else {
      // The first block 0x00 is read only, skip this
      if (uiBlock == 0)
        continue;

      // Make sure a earlier write did not fail
      if (!bFailure) {
        // Try to write the data block
        memcpy(mp.mpd.abtData, ptag->amb[uiBlock].mbd.abtData, 16);
        // Do not write a block 0 with incorrect BCC - card will be made invalid!
        if (uiBlock == 0) {
          if ((mp.mpd.abtData[0] ^ mp.mpd.abtData[1] ^ mp.mpd.abtData[2] ^ mp.mpd.abtData[3] ^ mp.mpd.abtData[4]) != 0x00) {
            printf("!\nError: incorrect BCC in MFD file!\n");
            printf("Expecting BCC=%02X\n", mp.mpd.abtData[0] ^ mp.mpd.abtData[1] ^ mp.mpd.abtData[2] ^ mp.mpd.abtData[3]);
            return false;
          }
        }
        if (!nfc_initiator_mifare_cmd(pnd, MC_WRITE, uiBlock, &mp))
          bFailure = true;
      }
    }
    // Show if the write went well for each block
    print_success_or_failure(bFailure, &uiWriteBlocks);
    if (bFailure)
      return false;
  }
  printf("|\n");
  printf("Done, %d of %d blocks written.\n", uiWriteBlocks, uiBlocks + 1);
  fflush(stdout);

  return true;
}

#if 0
int
_main(int argc, const char *argv[])
{
  action_t atAction = ACTION_USAGE;
  uint8_t *pbtUID;
  uint8_t _tag_uid[4];
  uint8_t *tag_uid = _tag_uid;

  int    unlock = 0;

  if (argc < 2) {
    print_usage(argv[0]);
    exit(EXIT_FAILURE);
  }
  const char *command = argv[1];

  if (argc < 5) {
    print_usage(argv[0]);
    exit(EXIT_FAILURE);
  }
  if (strcmp(command, "r") == 0 || strcmp(command, "R") == 0) {
    atAction = ACTION_READ;
    if (strcmp(command, "R") == 0)
      unlock = 1;
    bUseKeyA = tolower((int)((unsigned char) * (argv[2]))) == 'a';
    bTolerateFailures = tolower((int)((unsigned char) * (argv[2]))) != (int)((unsigned char) * (argv[2]));
    bUseKeyFile = (argc > 5);
    bForceKeyFile = ((argc > 6) && (strcmp((char *)argv[6], "f") == 0));
  } else if (strcmp(command, "w") == 0 || strcmp(command, "W") == 0 || strcmp(command, "f") == 0) {
    atAction = ACTION_WRITE;
    if (strcmp(command, "W") == 0)
      unlock = 1;
    bFormatCard = (strcmp(command, "f") == 0);
    bUseKeyA = tolower((int)((unsigned char) * (argv[2]))) == 'a';
    bTolerateFailures = tolower((int)((unsigned char) * (argv[2]))) != (int)((unsigned char) * (argv[2]));
    bUseKeyFile = (argc > 5);
    bForceKeyFile = ((argc > 6) && (strcmp((char *)argv[6], "f") == 0));
  }
  if (argv[3][0] == 'U') {
    unsigned long int _uid;

    if (strlen(argv[3]) != 9) {
      printf("Error, illegal tag specification, use U01ab23cd for example.\n");
      print_usage(argv[0]);
      exit(EXIT_FAILURE);
    }
    _uid = strtoul(argv[3] + 1, NULL, 16);
    tag_uid[0] = (_uid & 0xff000000UL) >> 24;
    tag_uid[1] = (_uid & 0x00ff0000UL) >> 16;
    tag_uid[2] = (_uid & 0x0000ff00UL) >> 8;
    tag_uid[3] = (_uid & 0x000000ffUL);
    printf("Attempting to use specific UID: 0x%2x 0x%2x 0x%2x 0x%2x\n",
           tag_uid[0], tag_uid[1], tag_uid[2], tag_uid[3]);
  } else {
    tag_uid = NULL;
  }

  if (atAction == ACTION_USAGE) {
    print_usage(argv[0]);
    exit(EXIT_FAILURE);
  }
  // We don't know yet the card size so let's read only the UID from the keyfile for the moment
  if (bUseKeyFile) {
    FILE *pfKeys = fopen(argv[5], "rb");
    if (pfKeys == NULL) {
      printf("Could not open keys file: %s\n", argv[5]);
      exit(EXIT_FAILURE);
    }
    if (fread(&mtKeys, 1, 4, pfKeys) != 4) {
      printf("Could not read UID from key file: %s\n", argv[5]);
      fclose(pfKeys);
      exit(EXIT_FAILURE);
    }
    fclose(pfKeys);
  }
  nfc_init(&context);
  if (context == NULL) {
    ERR("Unable to init libnfc (malloc)");
    exit(EXIT_FAILURE);
  }

// Try to open the NFC reader
  pnd = nfc_open(context, NULL);
  if (pnd == NULL) {
    ERR("Error opening NFC reader");
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  if (nfc_initiator_init(pnd) < 0) {
    nfc_perror(pnd, "nfc_initiator_init");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  };

// Let the reader only try once to find a tag
  if (nfc_device_set_property_bool(pnd, NP_INFINITE_SELECT, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
// Disable ISO14443-4 switching in order to read devices that emulate Mifare Classic with ISO14443-4 compliance.
  if (nfc_device_set_property_bool(pnd, NP_AUTO_ISO14443_4, false) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

// Try to find a MIFARE Classic tag
  int tags;

  tags = nfc_initiator_select_passive_target(pnd, nmMifare, tag_uid, tag_uid == NULL ? 0 : 4, &nt);
  if (tags <= 0) {
    printf("Error: no tag was found\n");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
// Test if we are dealing with a MIFARE compatible tag
  if ((nt.nti.nai.btSak & 0x08) == 0) {
    printf("Warning: tag is probably not a MFC!\n");
  }

// Get the info from the current tag
  pbtUID = nt.nti.nai.abtUid;

  if (bUseKeyFile) {
    uint8_t fileUid[4];
    memcpy(fileUid, mtKeys.amb[0].mbm.abtUID, 4);
// Compare if key dump UID is the same as the current tag UID, at least for the first 4 bytes
    if (memcmp(pbtUID, fileUid, 4) != 0) {
      printf("Expected MIFARE Classic card with UID starting as: %02x%02x%02x%02x\n",
             fileUid[0], fileUid[1], fileUid[2], fileUid[3]);
      printf("Got card with UID starting as:                     %02x%02x%02x%02x\n",
             pbtUID[0], pbtUID[1], pbtUID[2], pbtUID[3]);
      if (! bForceKeyFile) {
        printf("Aborting!\n");
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
      }
    }
  }
  printf("Found MIFARE Classic card:\n");
  print_nfc_target(&nt, false);

// Guessing size
  if ((nt.nti.nai.abtAtqa[1] & 0x02) == 0x02)
// 4K
    uiBlocks = 0xff;
  else if ((nt.nti.nai.btSak & 0x01) == 0x01)
// 320b
    uiBlocks = 0x13;
  else
// 1K/2K, checked through RATS
    uiBlocks = 0x3f;
// Testing RATS
  int res;
  if ((res = get_rats()) > 0) {
    if ((res >= 10) && (abtRx[5] == 0xc1) && (abtRx[6] == 0x05)
        && (abtRx[7] == 0x2f) && (abtRx[8] == 0x2f)
        && ((nt.nti.nai.abtAtqa[1] & 0x02) == 0x00)) {
      // MIFARE Plus 2K
      uiBlocks = 0x7f;
    }
    // Chinese magic emulation card, ATS=0978009102:dabc1910
    if ((res == 9)  && (abtRx[5] == 0xda) && (abtRx[6] == 0xbc)
        && (abtRx[7] == 0x19) && (abtRx[8] == 0x10)) {
      magic2 = true;
    }
  }
  printf("Guessing size: seems to be a %i-byte card\n", (uiBlocks + 1) * 16);

  if (bUseKeyFile) {
    FILE *pfKeys = fopen(argv[5], "rb");
    if (pfKeys == NULL) {
      printf("Could not open keys file: %s\n", argv[5]);
      exit(EXIT_FAILURE);
    }
    if (fread(&mtKeys, 1, (uiBlocks + 1) * sizeof(mifare_classic_block), pfKeys) != (uiBlocks + 1) * sizeof(mifare_classic_block)) {
      printf("Could not read keys file: %s\n", argv[5]);
      fclose(pfKeys);
      exit(EXIT_FAILURE);
    }
    fclose(pfKeys);
  }

  if (atAction == ACTION_READ) {
    memset(&mtDump, 0x00, sizeof(mtDump));
  } else {
    FILE *pfDump = fopen(argv[4], "rb");

    if (pfDump == NULL) {
      printf("Could not open dump file: %s\n", argv[4]);
      exit(EXIT_FAILURE);

    }

    if (fread(&mtDump, 1, (uiBlocks + 1) * sizeof(mifare_classic_block), pfDump) != (uiBlocks + 1) * sizeof(mifare_classic_block)) {
      printf("Could not read dump file: %s\n", argv[4]);
      fclose(pfDump);
      exit(EXIT_FAILURE);
    }
    fclose(pfDump);
  }
// printf("Successfully opened required files\n");

  if (atAction == ACTION_READ) {
    if (read_card(unlock)) {
      printf("Writing data to file: %s ...", argv[4]);
      fflush(stdout);
      FILE *pfDump = fopen(argv[4], "wb");
      if (pfDump == NULL) {
        printf("Could not open dump file: %s\n", argv[4]);
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
      }
      if (fwrite(&mtDump, 1, (uiBlocks + 1) * sizeof(mifare_classic_block), pfDump) != ((uiBlocks + 1) * sizeof(mifare_classic_block))) {
        printf("\nCould not write to file: %s\n", argv[4]);
        fclose(pfDump);
        nfc_close(pnd);
        nfc_exit(context);
        exit(EXIT_FAILURE);
      }
      printf("Done.\n");
      fclose(pfDump);
    }
  } else if (atAction == ACTION_WRITE) {
    write_card(unlock);
  }

  nfc_close(pnd);
  nfc_exit(context);
  exit(EXIT_SUCCESS);
}
#endif
