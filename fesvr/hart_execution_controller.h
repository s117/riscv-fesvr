/**
 * Controlling the execution of target HART via an HTIF link.
 */

#ifndef _HART_EXECUTION_CONTROLLER_H
#define _HART_EXECUTION_CONTROLLER_H
#include <functional>
#include <cstddef>
#include <vector>
#include <map>
#include "packet.h"
#include "hart_execution_reg.h"

class htif_t;

class hart_execution_controller_t
{
public:
  /**
   * Constant, the max number of PC breakpoints allowed.
   */
  static constexpr size_t MAX_PC_BREAKPOINT = 4;

  /**
   * Signature of the callback to handle breakpoint hit.
   *
   * The handler is responsible for continuing the execution from a breakpoint. This can be
   * done by calling defrost(hart_id, frozen_bit).
   *
   * The handler can set another same type breakpoint.
   *
   * @param controller Reference to the hart_execution_controller_t.
   * @param hart_id The HART ID of the triggering harts.
   * @param frozen_bit The bit to clear when defrost the harts from this breakpoint.
   */
  using breakpoint_handler_t = std::function<void(hart_execution_controller_t &controller, uint32_t hart_id, reg_t frozen_bit)>;

  /**
   * Constructor.
   * @param htif The HTIF this controller belongs to.
   */
  explicit hart_execution_controller_t(htif_t &htif) : m_htif(htif) {}

  /**
   * Initialize the controller. Must be called before setting any breakpoint.
   * @param num_hart The number of target HART(s).
   */
  void init(uint32_t num_hart);

  /**
   * Set a breakpoint based on number of instruction retired from now. The harts will be frozen after retired a give number of instructions.
   *
   * Once the breakpoint was successfully set, its tracking slot will remain active until the target hit the breakpoint.
   *
   * @param hart_id The HART ID of the harts being controlled.
   * @param trigger_incremental The harts will be frozen after retired this much instructions.
   * @param handler Handler to be called when the harts are frozen due to this breakpoint. The correlated tracking slot will be marked as
   *                inactive before calling this handler to allow the handler to set another same type breakpoint. Handler is responsible
   *                for defrost the harts at a proper time using the defrost() function.
   * @return True if the breakpoint slot is free and successfully configured. False if the breakpoint slot is being used.
   */
  bool set_instret_count_breakpoint(uint32_t hart_id, size_t trigger_incremental, const hart_execution_controller_t::breakpoint_handler_t &handler);

  /**
   * Clear the instruction retirement based breakpoint.
   *
   * If the harts has already hit the breakpoint and is frozen (but unaware to the controller yet), it will be defrost after this call.
   *
   * @param hart_id The HART ID of the harts being controlled.
   */
  void clear_instret_count_breakpoint(uint32_t hart_id);

  /**
   * Set a PC breakpoint. The harts will be frozen before executing the instruction from the specified PC. Note that freezing will not
   * happen if fetching from the specified PC results in a page fault. At maximum 4 active PC breakpoints is allowed.
   *
   * Once the breakpoint was successfully set, its tracking slot will remain active until the target hit the breakpoint.
   *
   * @param hart_id The HART ID of the harts being controlled.
   * @param pc The breakpoint PC.
   * @param handler Handler to be called when the harts are frozen due to this breakpoint. The correlated tracking slot will be marked as
   *                inactive before calling this handler to allow the handler to set another same type breakpoint. Handler is responsible
   *                for defrost the harts at a proper time using the defrost() function.
   * @return True if any PC breakpoint slot is free and successfully configured. False if all the PC breakpoint slots are being used or
   *         the specified PC has been previously configured and waiting to be triggered.
   */
  bool set_pc_breakpoint(uint32_t hart_id, addr_t pc, const breakpoint_handler_t &handler);

  /**
   * Clear a PC breakpoint.
   *
   * If the harts has already hit the breakpoint and is frozen (but unaware to the controller yet), it will be defrost after this call.
   *
   * @param hart_id The HART ID of the harts being controlled.
   * @param pc The PC to be cleared.
   */
  void clear_pc_breakpoint(uint32_t hart_id, addr_t pc);

  /**
   * Set an unconditional breakpoint. The specified harts harts will be frozen immediately when receiving this breakpoint.
   * @param hart_id The HART ID of the harts being controlled.
   * @param handler Handler to be called when the harts are frozen due to this breakpoint. The correlated tracking slot will be marked as
   *                inactive before calling this handler to allow the handler to set another same type breakpoint. Handler is responsible
   *                for defrost the harts at a proper time using the defrost() function.
   * @return True if the breakpoint slot is free and successfully configured. False if the breakpoint slot is being used.
   */
  bool set_unconditional_breakpoint(uint32_t hart_id, const breakpoint_handler_t &handler);

  /**
   * Clear the instruction retirement based breakpoint.
   *
   * If the harts has already hit the breakpoint and is frozen (but unaware to the controller yet), it will be defrost after this call.
   *
   * @param hart_id The HART ID of the harts being controlled.
   */
  void clear_unconditional_breakpoint(uint32_t hart_id);

  /**
   * Clear the frozen bit caused by a triggered breakpoint.
   *
   * The harts will be keep frozen until all the FROZEN bits are cleared.
   *
   * @param hart_id The HART ID of the harts being controlled.
   * @param frozen_bit Which FROZEN bit to clear.
   */
  void defrost(uint32_t hart_id, reg_t frozen_bit);

  htif_t &get_htif() { return m_htif; }

  /**
   * The FESVR should periodically call this function to allow the controller to poll execution state from each harts via the HTIF link.
   * @param hart_id The harts to poll state.
   */
  void do_poll(uint32_t hart_id);

private:
  /**
   * Internal function to handling the polling result from a frozen HART.
   * @param hart_id The harts being frozen.
   * @param frozen_reg The frozen bits read from that harts.
   */
  void on_hart_frozen(uint32_t hart_id, reg_t frozen_reg);

  struct breakpoint_slot_t
  {
    bool active = false;
    breakpoint_handler_t handler;
    uint64_t slot_data = 0;
  };

  using hart_breakpoint_slots_t = std::map<reg_t, breakpoint_slot_t>;
  std::vector<hart_breakpoint_slots_t> m_hart_bp_slots;
  htif_t &m_htif;
};


#endif //_HART_EXECUTION_CONTROLLER_H
