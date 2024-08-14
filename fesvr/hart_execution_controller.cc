//
// Created by john on 8/3/24.
//

#include "hart_execution_controller.h"
#include "htif.h"

static constexpr reg_t ALL_BREAKPOINT_MASKS[] = {
  EXE_CTRL_MASK_UNCONDITIONAL,
  EXE_CTRL_MASK_INSTR_CNT_DOWN,
  EXE_CTRL_MASK_PC0,
  EXE_CTRL_MASK_PC1,
  EXE_CTRL_MASK_PC2,
  EXE_CTRL_MASK_PC3,
};
static constexpr reg_t PC_BREAKPOINT_MASKS[] = {EXE_CTRL_MASK_PC0, EXE_CTRL_MASK_PC1, EXE_CTRL_MASK_PC2, EXE_CTRL_MASK_PC3};
static constexpr uint16_t PC_BREAKPOINT_REGNUM[] = {CR_EXE_CTRL_PC0_BREAK, CR_EXE_CTRL_PC1_BREAK, CR_EXE_CTRL_PC2_BREAK, CR_EXE_CTRL_PC3_BREAK};
static_assert(hart_execution_controller_t::MAX_PC_BREAKPOINT == sizeof(PC_BREAKPOINT_MASKS) / sizeof(*PC_BREAKPOINT_MASKS), "inconsistent pc_bp_mask definition");
static_assert(hart_execution_controller_t::MAX_PC_BREAKPOINT == sizeof(PC_BREAKPOINT_REGNUM) / sizeof(*PC_BREAKPOINT_REGNUM), "inconsistent pc_bp_regnum definition");

bool hart_execution_controller_t::set_unconditional_breakpoint(uint32_t hart_id, const breakpoint_handler_t &handler)
{
  auto &instret_count_bp_slot = m_hart_bp_slots[hart_id][EXE_CTRL_MASK_UNCONDITIONAL];
  if (instret_count_bp_slot.active)
    return false;

  assert((m_htif.read_hart_exec_ctrl_reg(hart_id, CR_EXE_CTRL_ENABLE) & EXE_CTRL_MASK_UNCONDITIONAL) == 0);

  instret_count_bp_slot.active = true;
  instret_count_bp_slot.handler = handler;
  m_htif.write_hart_exec_ctrl_reg(hart_id, CR_EXE_CTRL_ENABLE, EXE_CTRL_MASK_UNCONDITIONAL);

  return true;
}

void hart_execution_controller_t::clear_unconditional_breakpoint(uint32_t hart_id)
{
  m_htif.write_hart_exec_ctrl_reg(hart_id, CR_EXE_CTRL_RESET, EXE_CTRL_MASK_UNCONDITIONAL);
}

bool hart_execution_controller_t::set_instret_count_breakpoint(uint32_t hart_id, size_t trigger_incremental, const hart_execution_controller_t::breakpoint_handler_t &handler)
{
  auto &instret_count_bp_slot = m_hart_bp_slots[hart_id][EXE_CTRL_MASK_INSTR_CNT_DOWN];
  if (instret_count_bp_slot.active)
    return false;

  instret_count_bp_slot.active = true;
  instret_count_bp_slot.handler = handler;
  m_htif.write_hart_exec_ctrl_reg(hart_id, CR_EXE_CTRL_INSTR_CNT_DOWN, trigger_incremental);
  m_htif.write_hart_exec_ctrl_reg(hart_id, CR_EXE_CTRL_ENABLE, EXE_CTRL_MASK_INSTR_CNT_DOWN);

  return true;
}

void hart_execution_controller_t::clear_instret_count_breakpoint(uint32_t hart_id)
{
  m_htif.write_hart_exec_ctrl_reg(hart_id, CR_EXE_CTRL_RESET, EXE_CTRL_MASK_INSTR_CNT_DOWN);

  auto &instret_count_bp_slot = m_hart_bp_slots[hart_id][EXE_CTRL_MASK_INSTR_CNT_DOWN];
  instret_count_bp_slot.active = false;
  instret_count_bp_slot.handler = breakpoint_handler_t();
}

bool hart_execution_controller_t::set_pc_breakpoint(uint32_t hart_id, addr_t pc, const breakpoint_handler_t &handler)
{
  auto &bp_slots = m_hart_bp_slots[hart_id];
  for (size_t i = 0; i < MAX_PC_BREAKPOINT; i++)
  {
    auto &curr_pc_bp_slot = bp_slots[PC_BREAKPOINT_MASKS[i]];
    if (curr_pc_bp_slot.active)
    {
      // doesn't allow two slot breaks on the same PC
      if (curr_pc_bp_slot.slot_data == pc)
        return false;
    }
    else
    {
      curr_pc_bp_slot.active = true;
      curr_pc_bp_slot.handler = handler;
      curr_pc_bp_slot.slot_data = pc;
      m_htif.write_hart_exec_ctrl_reg(hart_id, PC_BREAKPOINT_REGNUM[i], pc);
      m_htif.write_hart_exec_ctrl_reg(hart_id, CR_EXE_CTRL_ENABLE, PC_BREAKPOINT_MASKS[i]);
      return true;
    }
  }
  return false;
}

void hart_execution_controller_t::clear_pc_breakpoint(uint32_t hart_id, addr_t pc)
{
  auto &bp_slots = m_hart_bp_slots[hart_id];
  for (unsigned long mask: PC_BREAKPOINT_MASKS)
  {
    auto &curr_pc_bp_slot = bp_slots[mask];
    if (curr_pc_bp_slot.active && curr_pc_bp_slot.slot_data == pc)
    {
      m_htif.write_hart_exec_ctrl_reg(hart_id, CR_EXE_CTRL_RESET, mask);
      curr_pc_bp_slot.active = false;
      curr_pc_bp_slot.handler = breakpoint_handler_t();
      return;
    }
  }
}


void hart_execution_controller_t::init(uint32_t num_hart)
{
  m_hart_bp_slots.clear();
  m_hart_bp_slots.resize(num_hart);
  for (uint32_t hart = 0; hart < num_hart; hart++)
  {
    m_htif.write_hart_exec_ctrl_reg(
      hart,
      CR_EXE_CTRL_RESET,
      EXE_CTRL_MASK_ALL);
    for (auto mask: ALL_BREAKPOINT_MASKS)
      m_hart_bp_slots[hart][mask] = breakpoint_slot_t();
  }
}

void hart_execution_controller_t::on_hart_frozen(uint32_t hart_id, reg_t frozen_reg)
{
  auto &hart_bp_slots = m_hart_bp_slots[hart_id];
  for (auto mask: ALL_BREAKPOINT_MASKS)
    if (frozen_reg & mask)
      if (hart_bp_slots[mask].active)
      {
        hart_bp_slots[mask].active = false;
        hart_bp_slots[mask].handler(*this, hart_id, mask);
      }
}

void hart_execution_controller_t::do_poll(uint32_t hart_id)
{
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
