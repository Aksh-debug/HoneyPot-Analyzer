import getopt
import ipaddress
import logs

def print_usage():
    """Prints correct command line usage of the app"""

    print("Usage: validator -t <target IP> <options>")
    logs.logger.info("Usage: validator -t <target IP> <options>")
    print("Options: ")
    logs.logger.info("Options: ")
    print("\t-O / --os-scan -> fingerprint OS (requires sudo)")
    logs.logger.info("\t-O / --os-scan -> fingerprint OS (requires sudo)")
    print("\t-l / --level= <level> -> maximum scanning level (1/2/3)")
    logs.logger.info("\t-l / --level= <level> -> maximum scanning level (1/2/3)")
    print("\t-p / --ports <port range> -> scan a specific range of ports (e.g. 20-100)."
          " For all ports use -p -")
    logs.logger.info("\t-p / --ports <port range> -> scan a specific range of ports (e.g. 20-100)."
          " For all ports use -p -")
    print("\t-f / --fast -> Uses -Pn and -T5 for faster scans on local connections")
    logs.logger.info("\t-f / --fast -> Uses -Pn and -T5 for faster scans on local connections")
    print("\t-b / --brief -> Disables NOT APPLICABLE tests for shorter output")
    logs.logger.info("\t-b / --brief -> Disables NOT APPLICABLE tests for shorter output")
    print("\t-s / --show <c/w> -> Show copyright/warning information")
    logs.logger.info("\t-s / --show <c/w> -> Show copyright/warning information")


def parse(argv):
    """
    Parses command line arguments and returns dict of requested options

    :param argv:
    :return: options dict
    """

    parsed = {
        "target": None,
        "scan_os": False,
        "scan_level": 5,
        "port_range": None,
        "fast": False,
        "brief": False
    }
    logs.logger.info(f'parsed : {parsed}')

    short_options = 't:l:Op:fbs:'
    logs.logger.info(f'short_options = {short_options}')
    long_options = ['target=', 'level=', 'os-scan', 'ports', 'fast','brief','show=']
    logs.logger.info(f'long_options = {long_options}')


    try:
        options, values = getopt.getopt(argv[1:], short_options, long_options)
        logs.logger.info(f'options : {options} , values : {values}')
        
    except getopt.GetoptError as opt_error:
        logs.logger.error(opt_error)
        print(opt_error)
        print_usage()
        return None

    for option, value in options:
        logs.logger.info(f'option : {option} , value : {value}')

        if option in ('-t', '--target'):
            logs.logger.info(f"{option} in ('-t', '--target')")
            parsed["target"] = value
        elif option in ('-l', '--level'):
            logs.logger.info(f"{option} in ('-l', '--level')")
            parsed["scan_level"] = int(value)
        elif option in ('-O', '--osscan'):
            logs.logger.info(f"{option} in ('-O', '--osscan')")
            parsed["scan_os"] = True
        elif option in ('-p', '--ports'):
            logs.logger.info(f"{option} in ('-p', '--ports')")
            parsed["port_range"] = value
        elif option in ('-f', '--fast'):
            logs.logger.info(f"{option} in ('-f', '--fast')")
            parsed["fast"] = True
        elif option in ('-b', '--brief'):
            logs.logger.info(f"{option} in ('-b', '--brief')")
            parsed["brief"] = True
        elif option in ('-s', '--show'):
            logs.logger.info(f"{option} in ('-s', '--show')")
            if value == 'c':
                print(
                    "COPYRIGHT ISSUED!!\n")
                logs.logger.critical('value == "c" , COPYRIGHT ISSUED!!')

            elif value == 'w':
                print(
                    "WARNING! WARNING!! WARNING!!!\n")
                logs.logger.warning('value == "w", WARNING! WARNING!! WARNING!!!')
            logs.logger.critical('EXIT!!')
            exit(0)

    # validate target IP
    # TODO convert this to use exceptions if it gets too big

    if parsed["target"] is None:
        logs.logger.info('parsed["target"] is None')
        print("No target specified. Use -t")
        logs.logger.info("No target specified. Use -t")
        print_usage()
        return None

    try:
        ipadd=ipaddress.ip_address(parsed["target"])
        logs.logger.info(ipadd)
    except ValueError:
        # not a valid ip address
        logs.logger.exception(ValueError)
        print("Target not a valid IP address")
        print_usage()
        return None
    
    return parsed

