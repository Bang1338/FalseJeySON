/*
    FalseJeySON
    Command line

    By bang1338
*/

#include "FJEncrypt.h"
#include "FJDecrypt.h"

#include <iostream>
#include <string>

int main(int argc, char* argv[]) {

    /*
        TODO:
        -cm:  Compressed
        -dcm: Decompressed
        -db:  Debug
    */
    if (argc < 5) {
        std::cout << "Usage: " << argv[0] << " [-e|-d] -i input.json -o output.json [-k key.fjkey]" << std::endl;
        return 1;
    }

    std::string mode, inputFile, outputFile, keyFile;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-e") {
            mode = "encrypt";

        }
        else if (arg == "-d") {
            mode = "decrypt";

        }
        else if (arg == "-i") {
            if (i + 1 < argc) {
                inputFile = argv[++i];
            }
            else {
                std::cout << "-i requires input file name" << std::endl;
                return 1;
            }

        }
        else if (arg == "-o") {
            if (i + 1 < argc) {
                outputFile = argv[++i];
            }
            else {
                std::cout << "-o requires output file name" << std::endl;
                return 1;
            }

        }
        else if (arg == "-k") {
            if (i + 1 < argc) {
                keyFile = argv[++i];
            }
            else {
                std::cout << "-k requires key file name" << std::endl;
                return 1;
            }
        }
    }

    if (mode.empty() || inputFile.empty()) {
        std::cout << "Missing required arguments" << std::endl;
        return 1;
    }

    if (mode == "encrypt") {
        FJEncrypt(inputFile, outputFile);

    }
    else if (mode == "decrypt") {
        if (keyFile.empty()) {
            std::cout << "Key file required for decrypt" << std::endl;
            return 1;
        }

        std::cout<< FJDecrypt(inputFile, keyFile);
    }

    return 0;
}