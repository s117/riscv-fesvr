//
// Created by john on 8/3/24.
//

#include "hart_execution_controller.h"
#include "htif.h"

static constexpr reg_t PC_BREAKPOINT_MASKS[] = {EXE_CTRL_MASK_PC0, EXE_CTRL_MASK_PC1, EXE_CTRL_MASK_PC2, EXE_CTRL_MASK_PC3};
static constexpr uint16_t PC_BREAKPOINT_REGNUM[] = {CR_EXE_CTRL_PC0_BREAK, CR_EXE_CTRL_PC1_BREAK, CR_EXE_CTRL_PC2_BREAK, CR_EXE_CTRL_PC3_BREAK};
static_assert(hart_execution_controller_t::MAX_PC_BREAKPOINT == sizeof(PC_BREAKPOINT_MASKS) / sizeof(*PC_BREAKPOINT_MASKS), "inconsistent pc_bp_mask definition");
static_assert(hart_execution_controller_t::MAX_PC_BREAKPOINT == sizeof(PC_BREAKPOINT_REGNUM) / sizeof(*PC_BREAKPOINT_REGNUM), "inconsistent pc_bp_regnum definition");
static_assert(EXE_CTRL_MASK_ALL == (1u << 6) - 1, "the breakpoint slots must be the low EXE_CTRL_MASK_* bits");

// index of a breakpoint slot in hart_breakpoints_t::slots, from its EXE_CTRL_MASK_* bit
static size_t slot_index(reg_t mask)
{
  return __builtin_ctzll(mask);
}

void hart_execution_controller_t::arm_slot(uint32_t hart_id, reg_t mask, breakpoint_handler_t handler, uint64_t slot_data)
{
  auto &hart_bps = m_hart_bps[hart_id];
  auto &slot = hart_bps.slots[slot_index(mask)];
  slot.handler = std::move(handler);
  slot.slot_data = slot_data;
  hart_bps.active |= mask;
}

void hart_execution_controller_t::disarm_slot(uint32_t hart_id, reg_t mask)
{
  auto &hart_bps = m_hart_bps[hart_id];
  hart_bps.active &= ~mask;
  hart_bps.slots[slot_index(mask)].handler = breakpoint_handler_t();
}

bool hart_execution_controller_t::set_unconditional_breakpoint(uint32_t hart_id, breakpoint_handler_t handler)
{
  if (m_hart_bps[hart_id].active & EXE_CTRL_MASK_UNCONDITIONAL)
    return false;

  arm_slot(hart_id, EXE_CTRL_MASK_UNCONDITIONAL, std::move(handler));
  m_htif.write_hart_exec_ctrl_reg(hart_id, CR_EXE_CTRL_ENABLE, EXE_CTRL_MASK_UNCONDITIONAL);

  return true;
}

void hart_execution_controller_t::clear_unconditional_breakpoint(uint32_t hart_id)
{
  m_htif.write_hart_exec_ctrl_reg(hart_id, CR_EXE_CTRL_RESET, EXE_CTRL_MASK_UNCONDITIONAL);
  disarm_slot(hart_id, EXE_CTRL_MASK_UNCONDITIONAL);
}

bool hart_execution_controller_t::set_instret_count_breakpoint(uint32_t hart_id, size_t trigger_incremental, breakpoint_handler_t handler)
{
  if (m_hart_bps[hart_id].active & EXE_CTRL_MASK_INSTR_CNT_DOWN)
    return false;

  arm_slot(hart_id, EXE_CTRL_MASK_INSTR_CNT_DOWN, std::move(handler));
  m_htif.write_hart_exec_ctrl_reg(hart_id, CR_EXE_CTRL_INSTR_CNT_DOWN, trigger_incremental);
  m_htif.write_hart_exec_ctrl_reg(hart_id, CR_EXE_CTRL_ENABLE, EXE_CTRL_MASK_INSTR_CNT_DOWN);

  return true;
}

void hart_execution_controller_t::clear_instret_count_breakpoint(uint32_t hart_id)
{
  m_htif.write_hart_exec_ctrl_reg(hart_id, CR_EXE_CTRL_RESET, EXE_CTRL_MASK_INSTR_CNT_DOWN);
  disarm_slot(hart_id, EXE_CTRL_MASK_INSTR_CNT_DOWN);
}

bool hart_execution_controller_t::set_pc_breakpoint(uint32_t hart_id, addr_t pc, breakpoint_handler_t handler)
{
  const auto &hart_bps = m_hart_bps[hart_id];
  // doesn't allow two slot breaks on the same PC
  for (auto mask: PC_BREAKPOINT_MASKS)
    if ((hart_bps.active & mask) && hart_bps.slots[slot_index(mask)].slot_data == pc)
      return false;

  for (size_t i = 0; i < MAX_PC_BREAKPOINT; i++)
  {
    if (hart_bps.active & PC_BREAKPOINT_MASKS[i])
      continue;
    arm_slot(hart_id, PC_BREAKPOINT_MASKS[i], std::move(handler), pc);
    m_htif.write_hart_exec_ctrl_reg(hart_id, PC_BREAKPOINT_REGNUM[i], pc);
    m_htif.write_hart_exec_ctrl_reg(hart_id, CR_EXE_CTRL_ENABLE, PC_BREAKPOINT_MASKS[i]);
    return true;
  }
  return false;
}

void hart_execution_controller_t::clear_pc_breakpoint(uint32_t hart_id, addr_t pc)
{
  const auto &hart_bps = m_hart_bps[hart_id];
  for (auto mask: PC_BREAKPOINT_MASKS)
  {
    if ((hart_bps.active & mask) && hart_bps.slots[slot_index(mask)].slot_data == pc)
    {
      m_htif.write_hart_exec_ctrl_reg(hart_id, CR_EXE_CTRL_RESET, mask);
      disarm_slot(hart_id, mask);
      return;
    }
  }
}


void hart_execution_controller_t::init(uint32_t num_hart)
{
  m_hart_bps.clear();
  m_hart_bps.resize(num_hart);
  for (uint32_t hart = 0; hart < num_hart; hart++)
    m_htif.write_hart_exec_ctrl_reg(hart, CR_EXE_CTRL_RESET, EXE_CTRL_MASK_ALL);
}

void hart_execution_controller_t::on_hart_frozen(uint32_t hart_id, reg_t frozen_reg)
{
  // a frozen bit without an active slot isn't handled
  reg_t pending = frozen_reg & m_hart_bps[hart_id].active;
  while (pending)
  {
    reg_t mask = pending & -pending;
    pending &= ~mask;
    // an earlier handler may have cleared this breakpoint
    if (!(m_hart_bps[hart_id].active & mask))
      continue;
    // Deactivate the slot before calling its handler, so the handler can set another breakpoint of the same type.
    // Move the handler out first: setting that breakpoint replaces the slot's handler, which must not happen to the
    // handler that is running.
    auto &slot = m_hart_bps[hart_id].slots[slot_index(mask)];
    breakpoint_handler_t handler = std::move(slot.handler);
    disarm_slot(hart_id, mask);
    handler(*this, hart_id, mask);
  }
}

void hart_execution_controller_t::do_poll(uint32_t hart_id)
{
  // Polling costs an HTIF round trip, skip it when no breakpoint is armed on this HART
  // (a frozen bit without an active slot isn't handled by on_hart_frozen() anyway).
  if (!m_hart_bps[hart_id].active)
    return;

  reg_t curr_frozen_reg = m_htif.read_hart_exec_ctrl_reg(hart_id, CR_EXE_CTRL_FROZEN);
  if (curr_frozen_reg)
  {
    on_hart_frozen(hart_id, curr_frozen_reg);
  }
}

void hart_execution_controller_t::defrost(uint32_t hart_id, reg_t frozen_bit)
{
  m_htif.write_hart_exec_ctrl_reg(hart_id, CR_EXE_CTRL_FROZEN, frozen_bit);
}
