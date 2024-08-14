//
// Created by john on 8/5/24.
//

#ifndef _FESVR_LOGGING_H
#define _FESVR_LOGGING_H

extern bool g_fesvr_verbose_output;

#define fesvr_log_verbose(file, args...) \
  if (g_fesvr_verbose_output) fprintf((file), ##args)

#define fesvr_log_normal(file, args...) \
  fprintf((file), ##args)

#endif //_FESVR_LOGGING_H
