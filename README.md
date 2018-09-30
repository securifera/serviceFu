# serviceFu
Automates credential skimming from service accounts in Windows Registry using Mimikatz lsadump::secrets. The use case for this tool is when you have administrative rights across certain computers in a domain but do not have any clear-text credentials. ServiceFu will remotely connect to target computers, check if any credentialed services are present, download the system and security registry hive, and decrypt clear-text credentials for the domain service account. The mimikatz project is located here: https://github.com/gentilkiwi/mimikatz

Usage:

    -h              print usage menu   
    -r              save registry hives   
    -o directory    directory to write registry hives   
    -i file         user accounts to ignore from results   
    -m              use mimikatz to decrypt service credentials   
    -t targets      target(s) - target computer(s) (default localhost).   
                    Accepts IP ranges and comma separated IPs
