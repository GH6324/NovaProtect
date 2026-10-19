#pragma once

#include <string>
#include <windows.h>

namespace np {

bool protectManagedExecutable(const std::wstring& input_path,
                              const std::wstring& output_path,
                              std::string& error);

}
