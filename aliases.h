#include <unordered_map>
#include <string>

const std::string& maybe_alias(const std::string& name) {
  const static std::unordered_map<std::string, std::string> lookup = {};
  auto it = lookup.find(name);
  if (it != lookup.end()) {
    return it->second;
  }
  return name;
}
