#include "ckpt_desc_reader.h"

#include <iostream>
#include <sstream>
#include <algorithm>
#include <set>
#include <map>
#include <fstream>

static std::string &ltrim(std::string &str, const std::string &chars = "\t\n\v\f\r ") {
  str.erase(0, str.find_first_not_of(chars));
  return str;
}

static std::string &rtrim(std::string &str, const std::string &chars = "\t\n\v\f\r ") {
  str.erase(str.find_last_not_of(chars) + 1);
  return str;
}

static std::string &trim(std::string &str, const std::string &chars = "\t\n\v\f\r ") {
  return ltrim(rtrim(str, chars), chars);
}

static std::pair<std::string, std::string> rsplit(std::string &s, char p) {
  auto pos = s.find_last_of(p);
  auto l = s.substr(0, pos);
  auto r = s.substr(pos + 1, s.size());
  return std::make_pair(l, r);
}

void ckpt_desc_print(const ckpt_desc_list_t &c) {
  std::cout << "Checkpoint(s) to create: " << std::endl;
  for (auto &it : c) {
    std::cout << "  Checkpoint: " << it.first << ", skip amount: " << it.second << std::endl;
  }
}

void ckpt_desc_validate(const ckpt_desc_list_t &c) noexcept(false) {
  // At least has one ckpt desc
  if (c.empty()) {
    throw std::runtime_error(std::string("empty checkpoint description list"));
  }

  std::map<size_t, ckpt_desc_t> unique_check_list;
  std::map<std::string, ckpt_desc_t> unique_name_check_list;
  for (auto &it: c) {
    // make sure each checkpoint has a unique name, otherwise a later checkpoint overwrites the earlier one's file
    if (!unique_name_check_list.count(it.first)) {
      unique_name_check_list[it.first] = it;
    } else {
      auto& conflict_a = unique_name_check_list[it.first];
      auto& conflict_b = it;

      throw std::runtime_error(
        std::string("Configurations has same checkpoint name:\n") +
        "  \"" + conflict_a.first + ": " + std::to_string(conflict_a.second) + "\" and\n" +
        "  \"" + conflict_b.first + ": " + std::to_string(conflict_b.second) + "\"\n"
      );
    }
    // make sure each checkpoint has a unique skip amount
    if (!unique_check_list.count(it.second)) {
      unique_check_list[it.second] = it;
    } else {
      auto& conflict_a = unique_check_list[it.second];
      auto& conflict_b = it;

      throw std::runtime_error(
        std::string("Configurations has same skip amount:\n") +
        "  \"" + conflict_a.first + ": " + std::to_string(conflict_a.second) + "\" and\n" +

        "  \"" + conflict_b.first + ": " + std::to_string(conflict_b.second) + "\"\n"
      );
    }
    // check illegal char in checkpoint name
    for (auto &ch: it.first)
      if (!(std::isalpha(ch) || std::isdigit(ch) || ch == '-' || ch == '_' || ch == '.'))
        throw std::runtime_error(
          "Configuration \"" + it.first + ": " + std::to_string(it.second) + "\" contains invalid char" +
          " (a valid checkpoint name can only contain char, digit, '-', '_', '.').\n"
        );
  }
}

ckpt_desc_list_t ckpt_desc_file_read(const std::string &filepath) noexcept(false) {
  ckpt_desc_list_t result;

  std::ifstream desc_file;
  desc_file.open(filepath, std::ios::in);
  if (!desc_file.good()) {
    throw std::runtime_error("Cannot open '" + filepath + "'.");
  }

  std::string line;
  while (desc_file.good()) {
    std::getline(desc_file, line);
    line = trim(line);
    if (line.empty())
      continue;
    if (line.find(':') == std::string::npos) {
      throw std::runtime_error("Configuration '" + line + "' has no ':' between the checkpoint name and its skip amount.");
    }
    auto lr_pair = rsplit(line, ':');
    lr_pair = std::make_pair(trim(lr_pair.first), trim(lr_pair.second));

    auto ckpt_name = lr_pair.first;
    if (ckpt_name.empty()) {
      throw std::runtime_error("Configuration '" + line + "' has an empty checkpoint name.");
    }
    std::istringstream ckpt_skip_amt_in_stream(lr_pair.second);
    size_t ckpt_skip_amt;

    // reject a sign explicitly: extracting a negative number into size_t wraps around instead of failing
    if (!lr_pair.second.empty() && (lr_pair.second[0] == '-' || lr_pair.second[0] == '+')) {
      throw std::runtime_error("Configuration '" + line + "' contains invalid skip amount.");
    }
    ckpt_skip_amt_in_stream >> ckpt_skip_amt;
    if (ckpt_skip_amt_in_stream.fail() or !ckpt_skip_amt_in_stream.eof()) {
      throw std::runtime_error("Configuration '" + line + "' contains invalid skip amount.");
    }

    result.emplace_back(ckpt_name, ckpt_skip_amt);

    //std::cout << lr_pair.first << "|" << lr_pair.second << std::endl;
  }

  std::sort(result.begin(), result.end(), [](const ckpt_desc_t &lhs, const ckpt_desc_t &rhs) {
    return lhs.second < rhs.second;
  });

  ckpt_desc_validate(result);

  return result;
}
