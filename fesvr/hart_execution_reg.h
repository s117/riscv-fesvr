/**
 * Pre-HART execution control registers.
 */

#ifndef _HART_EXECUTION_REG_H
#define _HART_EXECUTION_REG_H

/**
 * 1). Sequence to set instruction count breakpoint:
 *   1. Load CR_EXE_CTRL_INSTR_CNT_DOWN with number of instr. to execute until freeze.
 *   2. Set CR_EXE_CTRL_ENABLE[INSTR_CNT_DOWN_EN] to 1.
 *   3. The CR_EXE_CTRL_ENABLE[INSTR_CNT_DOWN_EN] bit will be cleared upon the harts is frozen due to the retired instruction count is met.
 * 2). Sequence to set a PC breakpoint:
 *   1. Load CR_EXE_CTRL_PCn_BREAK with desired PC.
 *   2. Set CR_EXE_CTRL_ENABLE[PCn_EN] to 1.
 *   3. The CR_EXE_CTRL_ENABLE[PCn_EN] will be cleared upon the harts is frozen due to fetched to the set PC.
 * 3). Check whether a harts is frozen for any reason:
 *   1. Read CR_EXE_CTRL_FROZEN, check any TRIG bit is set.
 * 4). Defrost a harts:
 *   1. Read CR_EXE_CTRL_FROZEN, get the reason why it is frozen.
 *   2. (optionally) Setup next debug state based on 1) and 2).
 *   3. Clear any set bits in CR_EXE_CTRL_FROZEN that causes the harts to be frozen.
 * 5). Freeze immediately:
 *   1. Set CR_EXE_CTRL_ENABLE[UNCONDITIONAL_EN] to 1.
 *   2.
 * 6). Reset a function:
 *   1. Write the corresponding bits to CR_EXE_CTRL_RESET.
 */

static constexpr size_t EXE_CTRL_MASK_UNCONDITIONAL = 1 << 0;
static constexpr size_t EXE_CTRL_MASK_INSTR_CNT_DOWN = 1 << 1;
static constexpr size_t EXE_CTRL_MASK_PC0 = 1 << 2;
static constexpr size_t EXE_CTRL_MASK_PC1 = 1 << 3;
static constexpr size_t EXE_CTRL_MASK_PC2 = 1 << 4;
static constexpr size_t EXE_CTRL_MASK_PC3 = 1 << 5;
static constexpr size_t EXE_CTRL_MASK_ALL = (EXE_CTRL_MASK_UNCONDITIONAL | EXE_CTRL_MASK_INSTR_CNT_DOWN | EXE_CTRL_MASK_PC0 | EXE_CTRL_MASK_PC1 | EXE_CTRL_MASK_PC2 | EXE_CTRL_MASK_PC3);

enum htif_hart_exec_ctrl_reg_t
{
  /**
   * NULL register, has no effect when read from or write to.
   */
  CR_EXE_CTRL_NULL = 0,

  /**
    * Read from RESET always returns 0.
    * Write to RESET will clear the corresponding bits in FROZEN and ENABLE.
    */
  CR_EXE_CTRL_RESET, /** PC3_RST  | PC2_RST  | PC1_RST  | PC0_RST  | INSTR_CNT_DOWN_RST  | UNCONDITIONAL_RST  */

  /**
   * Read from ENABLE will return the current enabled breakpoint trigger(s).
   * Write to ENABLE will enable the corresponding breakpoint trigger(s).
   * To clear a ENABLE bit before it is triggered, use the RESET control register.
   */
  CR_EXE_CTRL_ENABLE, /** PC3_EN   | PC2_EN   | PC1_EN   | PC0_EN   | INSTR_CNT_DOWN_EN   | UNCONDITIONAL_EN   */

  /**
    * Read from FROZEN will return the current frozen state.
    * If it is non-zero the bits tell which breakpoint(s) caused the harts entered frozen state.
    * Write to FROZEN will clear the frozen state caused by the bit being set.
    * The harts will be defrost once all frozen bits were cleared.
    */
  CR_EXE_CTRL_FROZEN, /** PC3_TRIG | PC2_TRIG | PC1_TRIG | PC0_TRIG | INSTR_CNT_DOWN_TRIG | UNCONDITIONAL_TRIG */
  CR_EXE_CTRL_INSTR_CNT_DOWN,
  CR_EXE_CTRL_PC0_BREAK,
  CR_EXE_CTRL_PC1_BREAK,
  CR_EXE_CTRL_PC2_BREAK,
  CR_EXE_CTRL_PC3_BREAK,
};

#endif //_HART_EXECUTION_REG_H
