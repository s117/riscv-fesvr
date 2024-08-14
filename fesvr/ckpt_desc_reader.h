#ifndef __CKPT_DESC_READER_H
#define __CKPT_DESC_READER_H

#include <vector>
#include <string>

typedef std::pair<std::string, size_t> ckpt_desc_t;
typedef std::vector<ckpt_desc_t> ckpt_desc_list_t;

void ckpt_desc_print(const ckpt_desc_list_t &c);

void ckpt_desc_validate(const ckpt_desc_list_t &c) noexcept(false);

ckpt_desc_list_t ckpt_desc_file_read(const std::string &filepath) noexcept(false);


#endif //__CKPT_DESC_READER_H
