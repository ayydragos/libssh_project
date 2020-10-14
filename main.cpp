#include "libssh/libsshpp.hpp"

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

std::tuple<std::string, std::string, std::string, std::string> readArgsFromFile(std::ifstream& file) {
    std::vector<std::string> args{};

    if (file.is_open()) {
        std::string arg{};
        while (std::getline(file, arg)) {
            args.emplace_back(arg.substr(arg.find('=') + 1));
        }

        file.close();
        if (args.size() == 4)
        {
            return std::make_tuple(args[0], args[1], args[2], args[3]);
        }
        else
        {
            throw std::runtime_error("Could not read all 4 args from the file");
        }
    }
    else
    {
        throw std::runtime_error("File cannot be opened");
    }
}

std::tuple<ssh_key, ssh_key> generateValidKeys()
{
    ssh_key privKey{};
    ssh_key pubKey{};

    if (ssh_pki_generate(SSH_KEYTYPE_RSA, 2048, &privKey) != SSH_OK)
    {
        throw std::runtime_error("Could not generate the private key");
    }

    if (ssh_pki_export_privkey_to_pubkey(privKey, &pubKey) != SSH_OK)
    {
        throw std::runtime_error("Could not create a public key from the previously created private key");
    }

    return std::make_tuple(privKey, pubKey);
}

void exportPublicKeyToFile(const ssh_key& pubKey, std::ofstream& outFile)
{
    char* base64 = nullptr;
    if (ssh_pki_export_pubkey_base64(pubKey, &base64) != SSH_OK)
    {
        throw std::runtime_error("Error converting public key to base64 string");
    }

    outFile << "ssh-rsa " << std::string{base64} << " dragos.ioan.fechete@ibm.com" << std::flush;
    outFile.close();

    std::free(base64);
}

// this function is called if password is provided in "input.txt"
void setUpSessionWithPassword(ssh::Session& session,
                  const std::string& username,
                  const std::string& password,
                  const std::string& host)
{
    session.setOption(SSH_OPTIONS_USER, username.c_str());
    session.setOption(SSH_OPTIONS_HOST, host.c_str());
    session.connect();

    if (!session.isServerKnown())
    {
        throw std::runtime_error("Server is not known");
    }

    if (session.userauthPassword(password.c_str()) != SSH_AUTH_SUCCESS)
    {
        throw std::runtime_error("Password does not match the user " + username);
    }
}

// this function is called if the "password" field of "input.txt" is empty
void setUpSessionWithPublicKey(ssh::Session& session,
                               const std::string& username,
                               const std::string& host)
{
    session.setOption(SSH_OPTIONS_USER, username.c_str());
    session.setOption(SSH_OPTIONS_HOST, host.c_str());
    session.connect();

    if (!session.isServerKnown())
    {
        throw std::runtime_error("Server is not known");
    }

    auto [privKey, pubKey] = generateValidKeys();

    std::ofstream auth_keys{};
    auth_keys.open("/Users/dragosioanfechete/.ssh/authorized_keys");

    exportPublicKeyToFile(pubKey, auth_keys);

    if (ssh_userauth_try_publickey(session.getCSession(), nullptr, pubKey) != SSH_AUTH_SUCCESS)
    {
        ssh_key_free(pubKey);
        ssh_key_free(privKey);
        throw std::runtime_error("Could not authenticate with public key");
    }

    if (ssh_userauth_publickey(session.getCSession(), nullptr, privKey) != SSH_AUTH_SUCCESS)
    {
        ssh_key_free(pubKey);
        ssh_key_free(privKey);
        throw std::runtime_error("Could not authenticate with private key");
    }

    ssh_key_free(pubKey);
    ssh_key_free(privKey);
}


std::string executeInstructionOnChannel(ssh::Channel& channel, const std::string& instruction)
{
    if (channel.isOpen())
    {
        channel.requestExec(instruction.c_str());

        // sleep is needed for the consistency of channel calls
        sleep(1);
        const auto size = channel.poll();
        char* buffer = new char[size];
        if (!channel.isEof())
        {
            channel.read(buffer, size, -1);
        }
        std::string returnString{buffer};
        delete[] buffer;
        return returnString;
    }
    else
    {
        throw std::runtime_error("Channel is not open");
    }
}


int main(int argc, char** argv)
{
    try
    {
        if (argc != 2) {
            throw std::runtime_error("The path to the file is required");
        }

        std::string path{argv[1]};
        std::ifstream file{path};
        auto [username, password, host, instruction] =  readArgsFromFile(file);

        ssh::Session session{};
        if (password.empty())
        {
            setUpSessionWithPublicKey(session, username, host);
        }
        else
        {
            setUpSessionWithPassword(session, username, password, host);
        }

        ssh::Channel channel{session};
        channel.openSession();

        std::cout << "For instruction `"
                  << instruction
                  << "` result is:\n"
                  << executeInstructionOnChannel(channel, instruction);

        channel.close();
    }
    catch (ssh::SshException& ex)
    {
        std::cout << "got ssh exception: " << ex.getError();
    }
    catch (const std::runtime_error& ex)
    {
        std::cout << "got runtime error: " << ex.what();
    }
    catch(...)
    {
        std::cout << "ex";
    }
    return 0;
}
