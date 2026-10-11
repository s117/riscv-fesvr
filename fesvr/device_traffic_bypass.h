// Classes to support device traffic bypassing between the ISA sim and MICRO sim in 721sim

#ifndef _DEVICE_TRAFFIC_BYPASS_H
#define _DEVICE_TRAFFIC_BYPASS_H
#include "device_composition.h"
#include <queue>
#include <vector>
#include <string>

class device_traffic_bypass_manager_t
{
public:
  static bool has_main_composition();

  static void set_main_composition(device_composition_t &main_composition);

  static device_composition_t &get_main_composition();

  /** The host path of the ELF the main FESVR loads at boot (empty if none), which a mirror FESVR loads too. */
  static void set_main_boot_elf(const std::string &path);

  static const std::string &get_main_boot_elf();

protected:
  static device_composition_t *g_main_composition;
  static std::string g_main_boot_elf;
};

#endif //_DEVICE_TRAFFIC_BYPASS_H
