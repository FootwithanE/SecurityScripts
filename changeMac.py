#!/usr/bin/env python

import subprocess
import optparse
import re

def getArguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change its MAC address")
    parser.add_option("-m", "--mac", dest="newMac", help="New MAC address")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("ERROR:You did not provide an interface! Use --help for info.")
    elif not options.newMac:
        parser.error("ERROR:You did not provide a MAC address! Use --help for info.")
    # Returns 2 values in tuple obj
    return options


def changeMac(interface, newMac):
    print("[+] Changing MAC of " + interface + " to " + newMac)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", newMac])
    subprocess.call(["ifconfig", interface, "up"])


def getCurrentMac(interface):
    ifconfigResult = subprocess.check_output(["ifconfig", interface])
    macAddressSearchResult = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfigResult)
    if macAddressSearchResult:
        return macAddressSearchResult.group(0)
    else:
        print("[-]ERROR: Could not find a MAC address.")


# tuple obj w/ 2 values
options = getArguments()
currentMac = getCurrentMac(options.interface)
print("Current MAC is " + str(currentMac))
changeMac(options.interface, options.newMac)
currentMac = getCurrentMac(options.interface)
if currentMac == options.newMac:
    print("[+] MAC change was successful. New MAC is " + currentMac)
else:
    print("[-] ERROR: MAC address not changed.")


