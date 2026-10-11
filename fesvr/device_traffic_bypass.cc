// Classes to support device traffic bypassing between the ISA sim and MICRO sim in 721sim

#include "device_traffic_bypass.h"

device_composition_t *device_traffic_bypass_manager_t::g_main_composition = nullptr;
std::string device_traffic_bypass_manager_t::g_main_boot_elf;

bool device_traffic_bypass_manager_t::has_main_composition() { return device_traffic_bypass_manager_t::g_main_composition != nullptr; }

void device_traffic_bypass_manager_t::set_main_composition(device_composition_t &main_composition)
{
  assert(!has_main_composition());
  device_traffic_bypass_manager_t::g_main_composition = &main_composition;
}

device_composition_t &device_traffic_bypass_manager_t::get_main_composition()
{
  return *device_traffic_bypass_manager_t::g_main_composition;
}

void device_traffic_bypass_manager_t::set_main_boot_elf(const std::string &path) { g_main_boot_elf = path; }

const std::string &device_traffic_bypass_manager_t::get_main_boot_elf() { return g_main_boot_elf; }
