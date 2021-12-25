#include <iostream>
#include <fstream>

#include "IO Handling/Input.h"
#include "includes/argparse.hpp"
#include "Base64/Base64.h"


int main(int argc, char** argv)
{
  argparse::ArgumentParser prog {"aes-cpp"};
  prog.add_argument("--file", "-f");
  prog.add_argument("--outfile", "-o");
  prog.add_argument("--password", "-p");
  prog.add_argument("--encrypt", "-e").implicit_value(true).default_value(false);
  prog.add_argument("--decrypt", "-d").implicit_value(true).default_value(false);

  try {
    prog.parse_args(argc, argv);
  } catch (const std::runtime_error& err) {
    std::cerr << err.what() << std::endl;
    std::cerr << prog;
    std::exit(2);
  }

  if (auto path_arg = prog.present("-f")) {
    AES::encrypt_file(path_arg.value(),
                      prog.present("-o"),
                      prog.present("-p"),
                      prog["--encrypt"] == true,
                      prog["--decrypt"] == true);
  } else {
    AES::interactive_mode();
  }

  return 0;
}
