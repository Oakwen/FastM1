#include <stdint.h>

static bool transmit_bits(const uint8_t *pbtTx, const size_t szTxBits);
static bool transmit_bytes(const uint8_t *pbtTx, const size_t szTx);
static void print_success_or_failure(bool bFailure, uint32_t *uiBlockCounter);
static bool is_first_block(uint32_t uiBlock);
static bool is_trailer_block(uint32_t uiBlock);
static uint32_t get_trailer_block(uint32_t uiFirstBlock);
static bool authenticate(uint32_t uiBlock);
static bool unlock_card(void);
static int get_rats(void);
static bool read_card(int read_unlocked);
static bool write_card(int write_block_zero);
// typedef enum { ACTION_READ, ACTION_WRITE, ACTION_USAGE } action_t;
void print_usage(const char *pcProgramName);
