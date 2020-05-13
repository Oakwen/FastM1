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

  // Display libnfc version
  acLibnfcVersion = nfc_version();
  printf("%s uses libnfc %s\n", argv[0], acLibnfcVersion);

  nfc_connstring connstrings[MAX_DEVICE_COUNT];
  size_t szDeviceFound =
      nfc_list_devices(context, connstrings, MAX_DEVICE_COUNT);

  if (szDeviceFound == 0) {
    printf("No NFC device found.\n");
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

