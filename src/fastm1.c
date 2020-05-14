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
 *
 *
 */

/**
 * @file fast-m1.c
 * @brief 快速读写M1卡
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif  // HAVE_CONFIG_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "err.h"
#include "nfc/nfc.h"
#include "mfclassic.h"
#include "nfc-utils.h"

#define MAX_DEVICE_COUNT 16
#define MAX_TARGET_COUNT 16

static nfc_device *pnd;

int main(int argc, const char *argv[]) {
  (void)argc;
  const char *acLibnfcVersion;
  size_t i;
  bool verbose = false;
  int res = 0;
  int mask = 0xff;
  int arg;

  nfc_context *context;
  nfc_init(&context);
  if (context == NULL) {
    ERR("Unable to init libnfc (malloc)");
    exit(EXIT_FAILURE);
  }

  // Display something
  print_usage("test");

  // Display libnfc version
  acLibnfcVersion = nfc_version();
  printf("%s uses libnfc %s\n", argv[0], acLibnfcVersion);

  nfc_connstring connstrings[MAX_DEVICE_COUNT];
  size_t szDeviceFound =
      nfc_list_devices(context, connstrings, MAX_DEVICE_COUNT);

  if (szDeviceFound == 0) {
    printf("No NFC device found.\n");
    exit(EXIT_FAILURE);
  }

  for (;;) {
    for (i = 0; i < szDeviceFound; i++) {
      nfc_target ant[MAX_TARGET_COUNT];
      pnd = nfc_open(context, connstrings[i]);

      if (pnd == NULL) {
        ERR("Unable to open NFC device: %s", connstrings[i]);
        continue;
      }
      if (nfc_initiator_init(pnd) < 0) {
        nfc_perror(pnd, "nfc_initiator_init");
        nfc_exit(context);
        exit(EXIT_FAILURE);
      }

      printf("NFC device: %s opened\n", nfc_device_get_name(pnd));

      nfc_modulation nm;

      nm.nmt = NMT_ISO14443A;
      nm.nbr = NBR_106;
      // List ISO14443A targets
      if ((res = nfc_initiator_list_passive_targets(pnd, nm, ant,
                                                    MAX_TARGET_COUNT)) >= 0) {
        int n;
        if (verbose || (res > 0)) {
          printf("%d ISO14443A passive target(s) found%s\n", res,
                 (res == 0) ? ".\n" : ":");
        }
        for (n = 0; n < res; n++) {
          print_nfc_target(&ant[n], verbose);
          printf("\n");
        }
      }
      nfc_close(pnd);
      printf("Press ENTER to continue, press Ctrl+C to exit.\n");
      fflush(stdin);
      getchar();
    }
  }

  nfc_exit(context);
  exit(EXIT_SUCCESS);
}
