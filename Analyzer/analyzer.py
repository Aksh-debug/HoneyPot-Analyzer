import logs
str='- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n'
logs.logger.info(str)
import sys
import os

import argv_parser
from honeypots.honeypot import Honeypot, ScanFailure
from tests.test_platform import TestPlatform


from tests import *


"""def first_run():
    '''Display terms the the first time user runs code'''

    acc_file = os.path.join(os.path.dirname(__file__), ".accepted")
    print(acc_file)

    if os.path.isfile(acc_file):
        return

    print(
        "YOU USE THIS PROGRAM AT YOUR OWN RISK!\n"
        "Please consult README.md for more information.\n"
        "By using this tool YOU TAKE FULL LEGAL RESPONSIBILITY FOR ANY\n"
        "POSSIBLE OUTCOME.\n"
    )

    print('Do you agree to these terms?')
    ans = input('Your answer [type in "i agree"/"no"]: ')

    while ans.lower() != 'i agree' and ans.lower() != 'no':
        print('Please answer with "i agree" or "no"!')
        ans = input('Your answer [type in "i agree"/"no"]: ')

    if ans.lower() == "i agree":
        with open(acc_file, 'w') as f:
            f.write('terms accepted')
    else:
        sys.exit(0)"""


def main(argv):
    '''"Entry point for the main application'''
   

    options = argv_parser.parse(argv)
    logs.logger.info(options)
    
    if options is None:
        sys.exit(2)
        logs.logger.warning("SYSYEM EXIT!!")

 
    #first_run()

    # run scan

    print("Running scan on " + options["target"])
    logs.logger.info("Running scan on " + options["target"])

    hp = Honeypot(options["target"], options["scan_os"],logfile=r'/home/kali/Project/analyzer/val_log.txt')
    logs.logger.info(hp)

    test_list = []
    logs.logger.info("test_list initialized")

    print("Scanning ports ...\n")
    logs.logger.info("Scanning ports ...")

    # collect data
    
    try:
        if options["port_range"]:
            hp.scan(port_range=options["port_range"], fast=options["fast"])   # restrict access to this?
           
        else:
            hp.scan()
    except ScanFailure as e:
        logs.logger.exception("Scan failed: " + str(e))
        print("Scan failed: " + str(e))
        sys.exit(1)
        logs.logger.warning('SYSYEM EXIT!!')

    # run tests

    if options["scan_level"] > 0:

        test_list.append(direct_fingerprinting.DirectFingerprintTest())
        #checks if the nmap scans directly fingerprints any service as a honeypot

        if options["scan_os"]:
            test_list.append(direct_fingerprinting.OSServiceCombinationTest())  
            #checks if the OS and running services makes sense

        test_list.append(direct_fingerprinting.DefaultServiceCombinationTest())  
        #checks if the running services combination is the default configuration for the default honeypots 
        
        test_list.append(direct_fingerprinting.DuplicateServicesCheck())  
        #checks if the machine is running duplicate services

    if options["scan_level"] > 1:
        test_list.append(default_ftp.DefaultFTPBannerTest())

        test_list.append(service_implementation.HTTPTest())
        test_list.append(default_http.DefaultWebsiteTest())
        test_list.append(default_http.DefaultGlastopfWebsiteTest())
        test_list.append(default_http.DefaultStylesheetTest())
        test_list.append(default_http.CertificateValidationTest())

        test_list.append(default_imap.DefaultIMAPBannerTest())

        test_list.append(default_smtp.DefaultSMTPBannerTest())
        test_list.append(service_implementation.SMTPTest())

        test_list.append(default_telnet.DefaultTelnetBannerTest())
        test_list.append(old_version_bugs.KippoErrorMessageBugTest())

        test_list.append(default_templates.DefaultTemplateFileTest())

    if options["scan_level"] > 2:
        pass

    tp = TestPlatform(test_list, hp, )
    logs.logger.info(tp)

    tp.run_tests(verbose=True, brief=options["brief"])


if __name__ == '__main__':
    main(sys.argv)
    
