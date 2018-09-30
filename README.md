# serviceFu
Automates credential skimming from service accounts in Windows Registry

serviceFu - Find credentialed services

Usage:
   -h              print usage menu
   -r              save registry hives
   -o directory    directory to write registry hives
   -i file         user accounts to ignore from results
   -m              use mimikatz to decrypt service credentials
   -t targets      target(s) - target computer(s) (default localhost).
                               Accepts IP ranges and comma separated IPs
