/*
* (C) 2009,2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"
#include <botan/version.h>
#include <iostream>
#include <algorithm>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/base_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"

int main(int argc, char* argv[]) {

	spdlog::set_pattern("[%H:%M:%S.%e][%-5!l][%-7!n] %^%v%$");
    spdlog::set_level(spdlog::level::info);

   	std::cerr << Botan::runtime_version_check(BOTAN_VERSION_MAJOR, BOTAN_VERSION_MINOR, BOTAN_VERSION_PATCH);

   	std::string cmd_name = "tls_server";
   	std::unique_ptr<Botan_CLI::Command> cmd(Botan_CLI::Command::get_cmd(cmd_name));
   	std::vector<std::string> args(argv + std::min(argc, 1), argv + argc);
   	return cmd->run(args);
}
