#include "grvt/result.hpp"
namespace grvt {
Error Error::config(std::string message) { return {ErrorKind::config, std::move(message)}; }
Error Error::signing(std::string message) { return {ErrorKind::signing, std::move(message)}; }
Error Error::decode(std::string context, std::string message) {
  return {ErrorKind::decode, context.empty() ? std::move(message) : context + ": " + message};
}
}  // namespace grvt
