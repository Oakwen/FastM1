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
 * Copyright (C) 2018-2019 Danielle Bruneo
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
 * Note that this license only applies on the examples, NFC library itself is
 * under LGPL
 *
 */

/**
 * @file nfc-mfclassic.c
 * @brief MIFARE Classic manipulation example
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif  // HAVE_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <locale.h>
#include <string.h>
#include <ctype.h>

#include <nfc/nfc.h>

#include "mifare.h"
#include "nfc-utils.h"

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
static bool magic3 = false;
static bool unlocked = false;
static bool bForceSizeMismatch;
static uint8_t uiBlocks;
static uint8_t keys[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xd3, 0xf7, 0xd3,
                         0xf7, 0xd3, 0xf7, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
                         0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0x4d, 0x3a, 0x99,
                         0xc3, 0x51, 0xdd, 0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a,
                         0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56};
static uint8_t default_key[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static uint8_t default_acl[] = {0xff, 0x07, 0x80, 0x69};

static const nfc_modulation nmMifare = {
    .nmt = NMT_ISO14443A,
    .nbr = NBR_106,
};

static size_t num_keys = sizeof(keys) / 6;

#define MAX_FRAME_LEN 264

static uint8_t abtRx[MAX_FRAME_LEN];
static int szRxBits;

uint8_t abtHalt[4] = {0x50, 0x00, 0x00, 0x00};

// special unlock command
uint8_t abtUnlock1[1] = {0x40};
uint8_t abtUnlock2[1] = {0x43};

static bool transmit_bits(const uint8_t *pbtTx, const size_t szTxBits) {
  // Show transmitted command
  printf("发送 bits:     ");
  print_hex_bits(pbtTx, szTxBits);
  // Transmit the bit frame command, we don't use the arbitrary parity feature
  if ((szRxBits = nfc_initiator_transceive_bits(
           pnd, pbtTx, szTxBits, NULL, abtRx, sizeof(abtRx), NULL)) < 0)
    return false;

  // Show received answer
  printf("接收 bits: ");
  print_hex_bits(abtRx, szRxBits);
  // Succesful transfer
  return true;
}

static bool transmit_bytes(const uint8_t *pbtTx, const size_t szTx) {
  // Show transmitted command
  printf("发送 bits:     ");
  print_hex(pbtTx, szTx);
  // Transmit the command bytes
  int res;
  if ((res = nfc_initiator_transceive_bytes(pnd, pbtTx, szTx, abtRx,
                                            sizeof(abtRx), 0)) < 0)
    return false;

  // Show received answer
  printf("接收 bits: ");
  print_hex(abtRx, res);
  // Succesful transfer
  return true;
}

static void print_success_or_failure(bool bFailure, uint32_t *uiBlockCounter) {
  printf("%c", (bFailure) ? 'x' : '.');
  if (uiBlockCounter && !bFailure) *uiBlockCounter += 1;
}

static bool is_first_block(uint32_t uiBlock) {
  // Test if we are in the small or big sectors
  if (uiBlock < 128)
    return ((uiBlock) % 4 == 0);
  else
    return ((uiBlock) % 16 == 0);
}

static bool is_trailer_block(uint32_t uiBlock) {
  // Test if we are in the small or big sectors
  if (uiBlock < 128)
    return ((uiBlock + 1) % 4 == 0);
  else
    return ((uiBlock + 1) % 16 == 0);
}

static uint32_t get_trailer_block(uint32_t uiFirstBlock) {
  // Test if we are in the small or big sectors
  uint32_t trailer_block = 0;
  if (uiFirstBlock < 128) {
    trailer_block = uiFirstBlock + (3 - (uiFirstBlock % 4));
  } else {
    trailer_block = uiFirstBlock + (15 - (uiFirstBlock % 16));
  }
  return trailer_block;
}

static bool authenticate(uint32_t uiBlock) {
  mifare_cmd mc;

  // Set the authentication information (uid)
  memcpy(mp.mpa.abtAuthUid, nt.nti.nai.abtUid + nt.nti.nai.szUidLen - 4, 4);

  // Should we use key A or B?
  mc = (bUseKeyA) ? MC_AUTH_A : MC_AUTH_B;

  // Key file authentication.
  if (bUseKeyFile) {
    // Locate the trailer (with the keys) used for this sector
    uint32_t uiTrailerBlock;
    uiTrailerBlock = get_trailer_block(uiBlock);

    // Extract the right key from dump file
    if (bUseKeyA)
      memcpy(mp.mpa.abtKey, mtKeys.amb[uiTrailerBlock].mbt.abtKeyA,
             sizeof(mp.mpa.abtKey));
    else
      memcpy(mp.mpa.abtKey, mtKeys.amb[uiTrailerBlock].mbt.abtKeyB,
             sizeof(mp.mpa.abtKey));

    // Try to authenticate for the current sector
    if (nfc_initiator_mifare_cmd(pnd, mc, uiBlock, &mp)) return true;

  } else if (magic3) {
    // If it's a One Time Write card, we're gonna authenticate with the default
    // keys
    memcpy(mp.mpa.abtKey, default_key, sizeof(default_key));

    // Try to authenticate for the current sector
    if (nfc_initiator_mifare_cmd(pnd, mc, uiBlock, &mp)) {
      return true;
    }
    // If formatting or not using key file, try to guess the right key
  } else if (bFormatCard || !bUseKeyFile) {
    for (size_t key_index = 0; key_index < num_keys; key_index++) {
      memcpy(mp.mpa.abtKey, keys + (key_index * 6), 6);
      if (nfc_initiator_mifare_cmd(pnd, mc, uiBlock, &mp)) {
        if (bUseKeyA)
          memcpy(mtKeys.amb[uiBlock].mbt.abtKeyA, &mp.mpa.abtKey,
                 sizeof(mtKeys.amb[uiBlock].mbt.abtKeyA));
        else
          memcpy(mtKeys.amb[uiBlock].mbt.abtKeyB, &mp.mpa.abtKey,
                 sizeof(mtKeys.amb[uiBlock].mbt.abtKeyB));
        return true;
      }
      if (nfc_initiator_select_passive_target(pnd, nmMifare, nt.nti.nai.abtUid,
                                              nt.nti.nai.szUidLen, NULL) <= 0) {
        ERR("卡片已被移除");
        return false;
      }
    }
  }

  return false;
}

static bool unlock_card(void) {
  // Configure the CRC
  if (nfc_device_set_property_bool(pnd, NP_HANDLE_CRC, false) < 0) {
    nfc_perror(pnd, "nfc_configure");
    return false;
  }
  // Use raw send/receive methods
  if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, false) < 0) {
    nfc_perror(pnd, "nfc_configure");
    return false;
  }

  iso14443a_crc_append(abtHalt, 2);
  transmit_bytes(abtHalt, 4);
  // now send unlock
  if (!transmit_bits(abtUnlock1, 7)) {
    printf("警告: 解锁命令 [1/2]: 失败 / 未确认.\n");
  } else {
    if (transmit_bytes(abtUnlock2, 1)) {
      printf("Card unlocked\n");
      unlocked = true;
    } else {
      printf("警告: 解锁命令 [2/2]: 失败 / 未确认.\n");
    }
  }

  // reset reader
  // Configure the CRC
  if (nfc_device_set_property_bool(pnd, NP_HANDLE_CRC, true) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    return false;
  }
  // Switch off raw send/receive methods
  if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, true) < 0) {
    nfc_perror(pnd, "nfc_device_set_property_bool");
    return false;
  }
  return true;
}

static int get_rats(void) {
  int res;
  uint8_t abtRats[2] = {0xe0, 0x50};
  // Use raw send/receive methods
  if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, false) < 0) {
    nfc_perror(pnd, "nfc_configure");
    return -1;
  }
  res = nfc_initiator_transceive_bytes(pnd, abtRats, sizeof(abtRats), abtRx,
                                       sizeof(abtRx), 0);
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
  // Reselect tag
  if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <= 0) {
    printf("错误: 卡片不见了\n");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  return res;
}

static bool read_card(int read_unlocked) {
  int32_t iBlock;
  bool bFailure = false;
  uint32_t uiReadBlocks = 0;

  if (read_unlocked) {
    // If the user is attempting an unlocked read, but has a direct-write type
    // magic card, they don't need to use the R mode. We'll trigger a warning
    // and let them proceed.
    if (magic2) {
      printf("提示: 本卡片读取无需解锁\n");
      read_unlocked = 0;
    } else {
      // If User has requested an unlocked read, but we're unable to unlock the
      // card, we'll error out.
      if (!unlock_card()) {
        return false;
      }
    }
  }

  printf("总共读取了 %d blocks |", uiBlocks + 1);
  // Read the card from end to begin
  for (iBlock = uiBlocks; iBlock >= 0; iBlock--) {
    // Authenticate everytime we reach a trailer block
    if (is_trailer_block(iBlock)) {
      if (bFailure) {
        // When a failure occured we need to redo the anti-collision
        if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <=
            0) {
          printf("!\n错误: 卡片已移除\n");
          return false;
        }
        bFailure = false;
      }

      fflush(stdout);

      // Try to authenticate for the current sector
      if (!read_unlocked && !authenticate(iBlock)) {
        printf("!\n错误: block 0x%02x 授权失败\n", iBlock);
        return false;
      }
      // Try to read out the trailer
      if (nfc_initiator_mifare_cmd(pnd, MC_READ, iBlock, &mp)) {
        if (read_unlocked) {
          memcpy(mtDump.amb[iBlock].mbd.abtData, mp.mpd.abtData,
                 sizeof(mtDump.amb[iBlock].mbd.abtData));
        } else {
          // If we're using a One Time Write ('Magic 3') Badge - we'll use
          // default keys + ACL
          if (magic3) {
            memcpy(mtDump.amb[iBlock].mbt.abtKeyA, default_key,
                   sizeof(default_key));
            memcpy(mtDump.amb[iBlock].mbt.abtAccessBits, mp.mpt.abtAccessBits,
                   sizeof(mtDump.amb[iBlock].mbt.abtAccessBits));
            memcpy(mtDump.amb[iBlock].mbt.abtKeyB, default_key,
                   sizeof(default_key));
          } else {
            // Copy the keys over from our key dump and store the retrieved
            // access bits
            memcpy(mtDump.amb[iBlock].mbt.abtKeyA,
                   mtKeys.amb[iBlock].mbt.abtKeyA,
                   sizeof(mtDump.amb[iBlock].mbt.abtKeyA));
            memcpy(mtDump.amb[iBlock].mbt.abtAccessBits, mp.mpt.abtAccessBits,
                   sizeof(mtDump.amb[iBlock].mbt.abtAccessBits));
            memcpy(mtDump.amb[iBlock].mbt.abtKeyB,
                   mtKeys.amb[iBlock].mbt.abtKeyB,
                   sizeof(mtDump.amb[iBlock].mbt.abtKeyB));
          }
        }
      } else {
        printf("!\n读取trailer block 0x%02x 失败\n", iBlock);
        bFailure = true;
      }
    } else {
      // Make sure a earlier readout did not fail
      if (!bFailure) {
        // Try to read out the data block
        if (nfc_initiator_mifare_cmd(pnd, MC_READ, iBlock, &mp)) {
          memcpy(mtDump.amb[iBlock].mbd.abtData, mp.mpd.abtData,
                 sizeof(mtDump.amb[iBlock].mbd.abtData));
        } else {
          printf("!\n错误: 无法读取 block 0x%02x\n", iBlock);
          bFailure = true;
        }
      }
    }
    // Show if the readout went well for each block
    print_success_or_failure(bFailure, &uiReadBlocks);
    if ((!bTolerateFailures) && bFailure) return false;
  }
  printf("|\n");
  printf("读卡完成, 总计 %d 扇区，已读取 %d 扇区.\n", uiBlocks + 1,
         uiReadBlocks);
  fflush(stdout);

  return true;
}

static bool write_card(int write_block_zero) {
  uint32_t uiBlock;
  bool bFailure = false;
  uint32_t uiWriteBlocks = 0;

  // Determine if we have to unlock the card
  if (write_block_zero) {
    // If the user is attempting an unlocked write, but has a direct-write type
    // magic card, they don't need to use the W mode. We'll trigger a warning
    // and let them proceed.
    if (magic2) {
      printf("提示: 本卡片写入无需解锁\n");
      write_block_zero = 0;
    } else {
      // If User has requested an unlocked write, but we're unable to unlock
      // the card, we'll error out.
      if (!unlock_card()) {
        return false;
      }
    }
  }

  printf("正在写入 %d blocks |", uiBlocks + 1);
  // Completely write the card, end to start, but skipping block 0
  for (uiBlock = 4; uiBlock <= uiBlocks; uiBlock++) {
    // Authenticate everytime we reach the first sector of a new block
    if (is_first_block(uiBlock)) {
      if (bFailure) {
        // When a failure occured we need to redo the anti-collision
        if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) <=
            0) {
          printf("!\nError: tag was removed\n");
          return false;
        }
        bFailure = false;
      }

      fflush(stdout);

      // Try to authenticate for the current sector
      // If we are are writing to a chinese magic card, we've already unlocked
      // If we're writing to a One Time Write card, we need to authenticate
      // If we're writing something else, we'll need to authenticate
      if ((write_block_zero && magic3) || !write_block_zero) {
        if (!authenticate(uiBlock) && !bTolerateFailures) {
          printf("!\nError: authentication failed for block %02x\n", uiBlock);
          return false;
        }
      }
    }

    if (is_trailer_block(uiBlock)) {
      if (bFormatCard) {
        // Copy the default key and reset the access bits
        memcpy(mp.mpt.abtKeyA, default_key, sizeof(mp.mpt.abtKeyA));
        memcpy(mp.mpt.abtAccessBits, default_acl, sizeof(mp.mpt.abtAccessBits));
        memcpy(mp.mpt.abtKeyB, default_key, sizeof(mp.mpt.abtKeyB));
      } else {
        // Copy the keys over from our key dump and store the retrieved access
        // bits
        memcpy(mp.mpt.abtKeyA, mtDump.amb[uiBlock].mbt.abtKeyA,
               sizeof(mp.mpt.abtKeyA));
        memcpy(mp.mpt.abtAccessBits, mtDump.amb[uiBlock].mbt.abtAccessBits,
               sizeof(mp.mpt.abtAccessBits));
        memcpy(mp.mpt.abtKeyB, mtDump.amb[uiBlock].mbt.abtKeyB,
               sizeof(mp.mpt.abtKeyB));
      }

      // Try to write the trailer
      if (nfc_initiator_mifare_cmd(pnd, MC_WRITE, uiBlock, &mp) == false) {
        printf("failed to write trailer block %d \n", uiBlock);
        bFailure = true;
      }
    } else {
      // The first block 0x00 is read only, skip this
      if (uiBlock == 0 && !write_block_zero && !magic2) continue;

      // Make sure a earlier write did not fail
      if (!bFailure) {
        // Try to write the data block
        if (bFormatCard && uiBlock) {
          memset(mp.mpd.abtData, 0x00, sizeof(mp.mpd.abtData));
          printf("WRITING");
        } else
          memcpy(mp.mpd.abtData, mtDump.amb[uiBlock].mbd.abtData,
                 sizeof(mp.mpd.abtData));
        // do not write a block 0 with incorrect BCC - card will be made
        // invalid!
        if (uiBlock == 0) {
          if ((mp.mpd.abtData[0] ^ mp.mpd.abtData[1] ^ mp.mpd.abtData[2] ^
               mp.mpd.abtData[3] ^ mp.mpd.abtData[4]) != 0x00 &&
              !magic2) {
            printf("!\nError: incorrect BCC in MFD file!\n");
            printf("Expecting BCC=%02X\n",
                   mp.mpd.abtData[0] ^ mp.mpd.abtData[1] ^ mp.mpd.abtData[2] ^
                       mp.mpd.abtData[3]);
            return false;
          }
        }
        if (!nfc_initiator_mifare_cmd(pnd, MC_WRITE, uiBlock, &mp)) {
          bFailure = true;
          printf("Failure to write to data block %i\n", uiBlock);
        }

      } else {
        printf("Failure during write process.\n");
      }
    }

    // Show if the write went well for each block
    print_success_or_failure(bFailure, &uiWriteBlocks);
    if ((!bTolerateFailures) && bFailure) return false;
  }

  // Write Block 0 if necessary
  if (write_block_zero || magic2 || magic3) {
    for (uiBlock = 0; uiBlock < 4; uiBlock++) {
      // printf("uiBlock= %d\n", uiBlock);
      // The first block 0x00 is read only, skip this
      if (uiBlock == 0) {
        // If the card is not magic, we're gonna skip over
        if (write_block_zero || magic2 || magic3) {
          // NOP
        } else {
          continue;
        }
      }

      if (is_first_block(uiBlock)) {
        if (bFailure) {
          // When a failure occured we need to redo the anti-collision
          if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0,
                                                  &nt) <= 0) {
            printf("!\n错误: 卡片已移除\n");
            return false;
          }
          bFailure = false;
        }

        fflush(stdout);
        // Try to authenticate for the current sector
        // If we are are writing to a chinese magic card, we've already unlocked
        // If we're writing to a One Time Write, we need to authenticate
        // If we're writing something else, we'll need to authenticate
        if ((write_block_zero && magic3) || !write_block_zero) {
          if (!authenticate(uiBlock) && !bTolerateFailures) {
            printf("!\n错误: block %02x 授权失败\n", uiBlock);
            return false;
          }
        }
      }

      // Make sure a earlier write did not fail
      if (!bFailure) {
        // Try to write the data block
        if (bFormatCard && uiBlock)
          memset(mp.mpd.abtData, 0x00, sizeof(mp.mpd.abtData));
        else {
          memcpy(mp.mpd.abtData, mtDump.amb[uiBlock].mbd.abtData,
                 sizeof(mp.mpd.abtData));
        }
        // do not write a block 0 with incorrect BCC - card will be made
        // invalid!
        if (uiBlock == 0) {
          if ((mp.mpd.abtData[0] ^ mp.mpd.abtData[1] ^ mp.mpd.abtData[2] ^
               mp.mpd.abtData[3] ^ mp.mpd.abtData[4]) != 0x00 &&
              !magic2) {
            printf("!\n错误: MFD文件的BCC值错误!\n");
            printf("期望的 BCC=%02X\n", mp.mpd.abtData[0] ^ mp.mpd.abtData[1] ^
                                            mp.mpd.abtData[2] ^
                                            mp.mpd.abtData[3]);
            return false;
          }
        }
        if (!nfc_initiator_mifare_cmd(pnd, MC_WRITE, uiBlock, &mp)) {
          bFailure = true;
          printf("写入 block %i 失败\n", uiBlock);
        }

      } else {
        printf("写入过程中发生错误.\n");
      }

      // Show if the write went well for each block
      print_success_or_failure(bFailure, &uiWriteBlocks);
      if ((!bTolerateFailures) && bFailure) return false;
    }
  }

  printf("|\n");
  printf("写入完成, 总计 %d 扇区，已写入 %d 扇区.\n", uiBlocks + 1,
         uiWriteBlocks);
  fflush(stdout);

  return true;
}

typedef enum { ACTION_READ, ACTION_WRITE, ACTION_USAGE } action_t;

// static void print_usage(const char *pcProgramName) {
//   printf("Usage: ");
//   printf("%s f|r|R|w|W a|b u|U<01ab23cd> <dump.mfd> [<keys.mfd> [f]]\n",
//          pcProgramName);
//   printf(
//       "  f|r|R|w|W     - Perform format (f) or read from (r) or unlocked read
//       " "from (R) or write to (w) or unlocked write to (W) card\n");
//   printf(
//       "                  *** format will reset all keys to FFFFFFFFFFFF and "
//       "all data to 00 and all ACLs to default\n");
//   printf(
//       "                  *** unlocked read does not require authentication
//       and " "will reveal A and B keys\n");
//   printf(
//       "                  *** note that unlocked write will attempt to "
//       "overwrite block 0 including UID\n");
//   printf(
//       "                  *** unlocking only works with special Mifare 1K
//       cards "
//       "(Chinese clones)\n");
//   printf(
//       "  a|A|b|B       - Use A or B keys for action; Halt on errors (a|b) or
//       " "tolerate errors (A|B)\n");
//   printf(
//       "  u|U           - Use any (u) uid or supply a uid specifically as "
//       "U01ab23cd.\n");
//   printf(
//       "  <dump.mfd>    - MiFare Dump (MFD) used to write (card to MFD) or
//       (MFD " "to card)\n");
//   printf(
//       "  <keys.mfd>    - MiFare Dump (MFD) that contain the keys
//       (optional)\n");
//   printf(
//       "  f             - Force using the keyfile even if UID does not match "
//       "(optional)\n");

//   printf("Examples: \n\n");
//   printf("  Read card to file, using key A:\n\n");
//   printf("    %s r a u mycard.mfd\n\n", pcProgramName);
//   printf("  Write file to blank card, using key A:\n\n");
//   printf("    %s w a u mycard.mfd\n\n", pcProgramName);
//   printf(
//       "  Write new data and/or keys to previously written card, using key "
//       "A:\n\n");
//   printf("    %s w a u newdata.mfd mycard.mfd\n\n", pcProgramName);
//   printf(
//       "  Format/wipe card (note two passes required to ensure writes for all
//       " "ACL cases):\n\n");
//   printf("    %s f A u dummy.mfd keyfile.mfd f\n", pcProgramName);
//   printf("    %s f B u dummy.mfd keyfile.mfd f\n\n", pcProgramName);
//   printf("  Read card to file, using key A and uid 0x01 0xab 0x23
//   0xcd:\n\n"); printf("    %s r a U01ab23cd mycard.mfd\n\n", pcProgramName);
// }

bool is_directwrite() {
  printf("Checking if Badge is DirectWrite...\n");

  // Set default keys
  memcpy(mtDump.amb[0].mbt.abtKeyA, default_key, sizeof(default_key));
  memcpy(mtDump.amb[0].mbt.abtAccessBits, default_acl,
         sizeof(mp.mpt.abtAccessBits));
  memcpy(mtDump.amb[0].mbt.abtKeyB, default_key, sizeof(default_key));

  // Temporarly override bUseKeyFile
  bool orig_bUseKeyFile = bUseKeyFile;
  bUseKeyFile = false;
  // Try to authenticate for the current sector
  if (!authenticate(0)) {
    printf("!\n错误: block 0x%02x 授权失败\n", 0);
    bUseKeyFile = orig_bUseKeyFile;
    return false;
  }
  // restore bUseKeyFile
  bUseKeyFile = orig_bUseKeyFile;

  // Try to read block 0
  uint8_t original_b0[16];
  if (nfc_initiator_mifare_cmd(pnd, MC_READ, 0, &mp)) {
    memcpy(original_b0, mp.mpd.abtData, sizeof(mp.mpd.abtData));
    printf(" 原始Block 0: ");
    for (int i = 0; i < 16; i++) {
      printf("%02x", original_b0[i]);
    }
    printf("\n");
    printf(" 原始UID: %02x%02x%02x%02x\n", original_b0[0], original_b0[1],
           original_b0[2], original_b0[3]);
  } else {
    printf("!\n错误: 无法读取 block 0x%02x\n", 0);
    return false;
  }

  printf(" Attempt to write Block 0 ...\n");
  memcpy(mp.mpd.abtData, original_b0, sizeof(original_b0));
  if (!nfc_initiator_mifare_cmd(pnd, MC_WRITE, 0, &mp)) {
    printf("将数据写入至 block %i 时发生错误\n", 0);
    return false;
  }
  printf(" Block 0 写入成功\n");

  return true;
}

int main(int argc, const char *argv[]) {
  setlocale(LC_ALL, "");

  action_t atAction = ACTION_USAGE;
  uint8_t *pbtUID;
  uint8_t _tag_uid[4];
  uint8_t *tag_uid = _tag_uid;
  const char *acLibnfcVersion;
  int unlock = 0;

  char *temp_file_data = "temp.dump";

  /////////////////////////////////////////////////////////////////////////////////////////
  // w a u temp.mfd
  // 参数：写卡模式，任意id，使用密钥A，将temp.dump文件内容写入，0号扇区不写。
  atAction = ACTION_READ;
  bUseKeyA = 1;
  bTolerateFailures = 0;
  bUseKeyFile = 0;
  bForceKeyFile = 0;
  tag_uid = NULL;
  bFormatCard = false;
  /////////////////////////////////////////////////////////////////////////////////////////

  nfc_init(&context);
  if (context == NULL) {
    ERR("无法初始化libnfc (malloc)");
    exit(EXIT_FAILURE);
  } else {
    acLibnfcVersion = nfc_version();
    printf("%s 使用libnfc版本: %s\n", argv[0], acLibnfcVersion);
  }

  // Try to open the NFC reader
  pnd = nfc_open(context, NULL);
  if (pnd == NULL) {
    ERR("打开NFC读卡器错误");
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }

  if (nfc_initiator_init(pnd) < 0) {
    nfc_perror(pnd, "nfc_initiator_init");
    nfc_close(pnd);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  };

  for (;;) {
    // for (int _loop = 1; _loop < 3; _loop++) {
    // atAction = (_loop % 2) ? ACTION_READ : ACTION_WRITE;
    atAction = ACTION_WRITE;
    // Let the reader only try once to find a tag
    if (nfc_device_set_property_bool(pnd, NP_INFINITE_SELECT, false) < 0) {
      nfc_perror(pnd, "nfc_device_set_property_bool");
      nfc_close(pnd);
      nfc_exit(context);
      exit(EXIT_FAILURE);
    }
    // Disable ISO14443-4 switching in order to read devices that emulate
    // Mifare Classic with ISO14443-4 compliance.
    if (nfc_device_set_property_bool(pnd, NP_AUTO_ISO14443_4, false) < 0) {
      nfc_perror(pnd, "nfc_device_set_property_bool");
      nfc_close(pnd);
      nfc_exit(context);
      exit(EXIT_FAILURE);
    }

    printf("NFC读卡器: %s 已打开\n", nfc_device_get_name(pnd));

    // Try to find a MIFARE Classic tag
    int tags;

    tags = nfc_initiator_select_passive_target(pnd, nmMifare, tag_uid,
                                               tag_uid == NULL ? 0 : 4, &nt);
    if (tags <= 0) {
      printf("错误: 未发现卡片\n");
      nfc_close(pnd);
      nfc_exit(context);
      exit(EXIT_FAILURE);
    }
    // Test if we are dealing with a MIFARE compatible tag
    if ((nt.nti.nai.btSak & 0x08) == 0) {
      printf("警告: 卡片可能不是MFC卡!\n");
    }

    // Get the info from the current tag
    pbtUID = nt.nti.nai.abtUid;

    if (bUseKeyFile) {
      uint8_t fileUid[4];
      memcpy(fileUid, mtKeys.amb[0].mbm.abtUID, 4);
      // Compare if key dump UID is the same as the current tag UID, at least
      // for the first 4 bytes
      if (memcmp(pbtUID, fileUid, 4) != 0) {
        printf(
            "MF1的UID应以: "
            "%02x%02x%02x%02x 开头。\n",
            fileUid[0], fileUid[1], fileUid[2], fileUid[3]);
        printf(
            "获取到的MF卡UID以:           "
            "%02x%02x%02x%02x    开头\n",
            pbtUID[0], pbtUID[1], pbtUID[2], pbtUID[3]);
        if (!bForceKeyFile) {
          printf("正在退出!\n");
          nfc_close(pnd);
          nfc_exit(context);
          exit(EXIT_FAILURE);
        }
      }
    }
    printf("发现MF卡:\n");
    print_nfc_target(&nt, false);

    // Guessing size
    if ((nt.nti.nai.abtAtqa[1] & 0x02) == 0x02 || nt.nti.nai.btSak == 0x18)
      // 4K
      uiBlocks = 0xff;
    else if (nt.nti.nai.btSak == 0x09)
      // 320b
      uiBlocks = 0x13;
    else
      // 1K/2K, checked through RATS
      uiBlocks = 0x3f;
    // Testing RATS
    int res;
    if ((res = get_rats()) > 0) {
      printf("RATS: 支持\n");
      if ((res >= 10) && (abtRx[5] == 0xc1) && (abtRx[6] == 0x05) &&
          (abtRx[7] == 0x2f) && (abtRx[8] == 0x2f) &&
          ((nt.nti.nai.abtAtqa[1] & 0x02) == 0x00)) {
        // MIFARE Plus 2K
        uiBlocks = 0x7f;
      }
      // Chinese magic emulation card, ATS=0978009102:dabc1910
      if ((res == 9) && (abtRx[5] == 0xda) && (abtRx[6] == 0xbc) &&
          (abtRx[7] == 0x19) && (abtRx[8] == 0x10)) {
        magic2 = true;
        printf("这是一张中国魔术卡.\n");
      }
    } else
      printf("RATS : 不支持\n");
    printf("猜测卡片容量: 开起来这是一张 %lu-byte 的卡片\n",
           (unsigned long)((uiBlocks + 1) * sizeof(mifare_classic_block)));

    // If size is 4k check for direct-write card
    if (uiBlocks == 0xff) {
      if (is_directwrite()) {
        printf("卡片支持直接写入\n");
        magic3 = true;
        unlock = 0;
      } else {
        printf("卡片不支持直接写入\n");
      }
    }

    // Check to see if we have a One Time Write badge (magic3)
    if (pbtUID[0] == 0xaa && pbtUID[1] == 0x55 && pbtUID[2] == 0xc3 &&
        pbtUID[3] == 0x96) {
      printf("卡片可能是一次写入卡(magic)..\n");
      magic3 = true;
      unlock = 0;
    }

    // if (bUseKeyFile) {
    //   FILE *pfKeys = fopen(argv[5], "rb");
    //   if (pfKeys == NULL) {
    //     printf("找不到密钥文件: %s\n", argv[5]);
    //     exit(EXIT_FAILURE);
    //   }
    //   if (fread(&mtKeys, 1, (uiBlocks + 1) * sizeof(mifare_classic_block),
    //             pfKeys) != (uiBlocks + 1) * sizeof(mifare_classic_block)) {
    //     printf("无法读取密钥文件: %s\n", argv[5]);
    //     fclose(pfKeys);
    //     exit(EXIT_FAILURE);
    //   }
    //   fclose(pfKeys);
    // }

    if (atAction == ACTION_READ) {
      memset(&mtDump, 0x00, sizeof(mtDump));
    } else {
      FILE *pfDump = fopen(temp_file_data, "rb");

      if (pfDump == NULL) {
        printf("找不到dump文件: %s\n", temp_file_data);
        exit(EXIT_FAILURE);
      }

      if (fread(&mtDump, 1, (uiBlocks + 1) * sizeof(mifare_classic_block),
                pfDump) != (uiBlocks + 1) * sizeof(mifare_classic_block)) {
        printf("无法读取dump文件: %s\n", temp_file_data);
        fclose(pfDump);
        exit(EXIT_FAILURE);
      }
      fclose(pfDump);
    }
    // printf("Successfully opened required files\n");

    if (atAction == ACTION_READ) {
      if (read_card(unlock)) {
        printf("正在写入数据至文件: %s ...", temp_file_data);
        fflush(stdout);
        FILE *pfDump = fopen(temp_file_data, "wb");
        if (pfDump == NULL) {
          printf("未发现dump文件: %s\n", temp_file_data);
          nfc_close(pnd);
          nfc_exit(context);
          exit(EXIT_FAILURE);
        }
        if (fwrite(&mtDump, 1, (uiBlocks + 1) * sizeof(mifare_classic_block),
                   pfDump) != ((uiBlocks + 1) * sizeof(mifare_classic_block))) {
          printf("\n无法写入至文件: %s\n", temp_file_data);
          fclose(pfDump);
          nfc_close(pnd);
          nfc_exit(context);
          exit(EXIT_FAILURE);
        }
        printf("已完成读取.\n");
        fclose(pfDump);
      }
    } else if (atAction == ACTION_WRITE) {
      write_card(unlock);
    }
    // }
    // printf("Press ENTER to continue, press Ctrl+C to exit.\n");
    printf("按Enter键继续, 按Ctrl+C键退出.\n");
    fflush(stdin);
    getchar();
  }
  nfc_close(pnd);
  nfc_exit(context);
  exit(EXIT_SUCCESS);
}
