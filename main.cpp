#include <iostream>

#include "IO Handling/Input.h"
#include "includes/argparse.hpp"

int main(int argc, char** argv)
{
  argparse::ArgumentParser prog {"aes-cpp"};
  prog.add_argument("--key", "-k");

  try {
    prog.parse_args(argc, argv);
  } catch (const std::runtime_error& err) {
    std::cerr << err.what() << std::endl;
    std::cerr << prog;
    std::exit(2);
  }

  if (auto key = prog.present("-k")) {
    std::cout << "KEY PROVIDED: " << key.value() << "\n";
  } else {
    AES::interactive_mode();
  }

  return 0;
}
