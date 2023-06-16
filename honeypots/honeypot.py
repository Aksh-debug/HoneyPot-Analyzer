import nmap
#print(dir(nmap3))
import platform
import urllib.request
import urllib.error
import socket
import time
import logs


class Honeypot:
    """
    Holds all data known about one Honeypot.
    Used for decoupling the acquisition of the data from its usages.
    """

    __debug = False  # enables debug prints
    logs.logger.info("__debug = False")
    scan_id = 0
    logs.logger.info("scan_id = 0")
    websites = []  # cached web page data for current honeypot
    logs.logger.info("websites = []")
    css = []  # cached css data for current honeypot
    logs.logger.info("css = []")

    def __init__(self, address, scan_os=False, verbose_scan=True,logfile=None):
        """
        :param address: ip address of the target
        :param scan_os: scan for Operating System information (requires elevated privileges)
        :param verbose_scan: print progress bars and stats when running a scan
        """
        self.address = address
        logs.logger.info(f'self.address = {self.address}')
        self.scan_os = scan_os
        logs.logger.info(f'self.scan_os = {self.scan_os}')
        self.host = None
        logs.logger.info(f'self.host = {self.host}')
        self._logfile = logfile
        logs.logger.info(f'self._logfile = {self._logfile}')

        if verbose_scan:
            try:
                self._nm = nmap.PrintProgressPortScanner()
                logs.logger.info(f'self._nm = {self._nm}')
            except AttributeError:
                # not running the modded version of python-nmap
                logs.logger.exception(AttributeError)
                logs.logger.warning("Cannot display progress bars as you have an unsupported version of python-nmap. "
                      "Please install from requirements.txt. Example: pip install -r requirements.txt")
                self._nm = nmap.PortScanner()
                logs.logger.info(f'self._nm = {self._nm}')
        else:
            self._nm = nmap.PortScanner()
            logs.logger.info(f'self._nm = {self._nm}')
    def _log(self,*args):
        if(self._logfile):
            with open(self._logfile,'a') as f:
                print(*args,file=f)

    def scan(self, port_range=None, fast=False):
        """
        Runs a scan for data acquisition.
        """

        args = '-sV -n --stats-every 1s'
        logs.logger.info(f'args = {args}')

        if fast:
            logs.logger.info(f'fast : {fasr}')
            args += ' -Pn -T5'
            logs.logger.info(f'args = {args}')

        if port_range:
            logs.logger.info(f'port_range : {port_range}')
            args += ' -p '+port_range
            logs.logger.info(f'args = {args}')

        if self.scan_os:
            logs.logger.info(f'scan_os : {self.scan_os}')
            args += ' -O'
            logs.logger.info(f'args = {args}')

            if platform.system() == 'Windows':
                logs.logger.info("platform.system() == 'Windows'")
                # No sudo on Windows systems, let UAC handle this
                #  workaround for the subnet python-nmap-bug.log also?
                #  somehow this also makes the command history of the terminal vanish?
                self._nm.scan(hosts=self.address, arguments=args, sudo=False)
            else:
                try:
                    logs.logger.info("platform.system() == 'Not Windows'")
                    # this is just a workaround for the bug shown in python-nmap-bug.log
                    a=self._nm.scan(hosts=self.address, arguments=args, sudo=True)
                    logs.logger.info(a)
                    if(a):
                        self._log(time.ctime(),' : ',a)
                except Exception as e:
                    self.logger.exception(Exception)
                    if self.__debug:
                        print(e.__class__, "occured trying again with get_last_output")
                        logs.logger.warning(f'{e.__class__} occured trying again with get_last_output')
                    self._nm.get_nmap_last_output()
                    a=self._nm.scan(hosts=self.address, arguments=args, sudo=True)
                    logs.logger.info(a)
                    if(a):
                        self._log(time.ctime(),' : ',a)
        else:

            try:
                # this is just a workaround for the bug shown in python-nmap-bug.log
                a=self._nm.scan(hosts=self.address, arguments=args, sudo=False)
                logs.logger.info(a)
                if(a):
                    self._log(time.ctime(),' : ',a)
                    
            #print('- - - - - - - - -- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - --\n')
            except Exception as e:
                if self.__debug:
                    print(e.__class__, "occured trying again with get_last_output")
                    logs.logger.warning(f'{e.__class__} occured trying again with get_last_output')
                self._nm.get_nmap_last_output()
                a=self._nm.scan(hosts=self.address, arguments=args, sudo=False)
                logs.logger.info(a)
                if(a):
                    self._log(time.ctime(),' : ',a)
	# Return all open ports of honeypot
        hosts = self._nm.all_hosts()
        logs.logger.info(f'hosts = {hosts}')

        if hosts:
            self.host = hosts[0]
            logs.logger.info(f'self.host = {self.host}')
        else:
            self.host = None
            logs.logger.info(f'self.host = {self.host}')
            logs.logger.exception(ScanFailure)
            raise ScanFailure("Requested host not available")

        #error on connection refused, check if self._nm[self.host]['status']['reason'] = conn_refused
        #also add -Pn option?

    @property
    def os(self):
        if self.scan_os and self.host and 'osmatch' in self._nm[self.host]:
            if self._nm[self.host]['osmatch'] and self._nm[self.host]['osmatch'][0]['osclass']:
                logs.logger.info(f"self._nm[self.host]['osmatch'][0]['osclass'][0]['osfamily'] : {self._nm[self.host]['osmatch'][0]['osclass'][0]['osfamily']}")
                return self._nm[self.host]['osmatch'][0]['osclass'][0]['osfamily']

    @property
    def ip(self):
        logs.logger.info(f"self._nm[self.host]['addresses']['ipv4'] : {self._nm[self.host]['addresses']['ipv4']}")
        return self._nm[self.host]['addresses']['ipv4']

    def has_tcp(self, port_number):
        """
        Checks if the Honeypot has a certain port open.
        :param port_number: port number
        :return: port status boolean
        """
        logs.logger.info(f"self._nm[self.host].has_tcp(port_number) : {self._nm[self.host].has_tcp(port_number)}")
        return self._nm[self.host].has_tcp(port_number)

    def get_service_ports(self, service_name, protocol):
        """
        Checks if the Honeypot has a certain service available.
        :param service_name: name of the service to search for
        :param protocol: 'tcp' or 'udp'
        :return: list of port numbers (a certain service can run on multiple ports)
        """
        results = []
        logs.logger.info('results = []')

        if protocol not in self._nm[self.host]:
            logs.logger.info('protocol not in self._nm[self.host]')
            logs.logger.info(f'results : {results}')
            return results

        for port, attributes in self._nm[self.host][protocol].items():
            if attributes['name'] == service_name:
                logs.logger.info("Condition True : attributes['name'] == service_name")
                results.append(port)
             
        logs.logger.info(f'results : {results}')
        return results

    def get_service_name(self, port, protocol):
        """
        Get name of service running on requested port
        :param port: target port
        :param protocol: 'tcp' or 'udp'
        :return: service name
        """
        if protocol not in self._nm[self.host]:
            logs.logger.info('protocol not in self._nm[self.host]')
            return None
        logs.logger.info(f'self._nm[self.host][protocol][port]["name"] : {self._nm[self.host][protocol][port]["name"]}')
        return self._nm[self.host][protocol][port]["name"]

    def get_all_ports(self, protocol):
        """
        Returns all open ports on the honeypot
        :param protocol: 'tcp' / 'udp'
        :return: list of ports
        """
        if protocol not in self._nm[self.host]:
            logs.logger.info('protocol not in self._nm[self.host]')
            return []
        else:
            logs.logger.info(f"self._nm[self.host][protocol]).keys() : {list((self._nm[self.host][protocol]).keys())}")
            return list((self._nm[self.host][protocol]).keys())

    def get_service_product(self, protocol, port):
        """
        Get the product description for a certain port
        :param protocol: 'tcp' / 'udp'
        :param port: port number
        :return: description string
        """
        # TODO cache requests for all parsers
        if protocol not in self._nm[self.host]:
            logs.logger.info('protocol not in self._nm[self.host]')
            return None
        else:
            logs.logger.info(f"self._nm[self.host][protocol][port]['product'] : {self._nm[self.host][protocol][port]['product']}")
            return self._nm[self.host][protocol][port]['product']

    def run_nmap_script(self, script, port, protocol='tcp'):
        """
        Runs a .nse script on the specified port range
        :param script: <script_name>.nse
        :param port: port / port range
        :param protocol: 'tcp'/'udp'
        :return: script output as string
        :raises: ScanFailure
        """

        tmp = nmap.PortScanner()
        logs.logger.info(f"tmp = {tmp}")
        tscan=tmp.scan(hosts=self.address, arguments="--script " + script + " -p " + str(port))
        logs.logger.info(f'tmp.scan = {tscan}')

        port_info = tmp[self.address][protocol][int(port)]
        logs.logger.info(f"port_info = {port_info}")

        if 'script' in port_info:
            logs.logger.info("script' in port_info")
            logs.logger.info(f"port_info['script'][script.split('.')[0]] : {port_info['script'][script.split('.')[0]]}")
            return port_info['script'][script.split('.')[0]]
        else:
            logs.logger.exception(ScanFailure)
            raise ScanFailure("Script execution failed")

    def get_banner(self, port, protocol='tcp'):
        """
        Grab banner on specified port
        :param port: port number
        :param protocol: 'tcp' / 'udp'
        :return: banner as string
        :raises: ScanFailure
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logs.logger.info(s)
        s.settimeout(5)

        try:
            conn=s.connect((self.address, port))
            logs.logger.info(conn)
            recv = s.recv(1024)
            logs.logger.info(recv)
        except socket.error as e:
            logs.logger.exception(ScanFailure)
            raise ScanFailure("Banner grab failed for port", port, e)
        logs.logger.info(recv)
        return recv

    def get_websites(self):
        """
        Gets websites for all active web servers found on the target
        :return: list of website content strings
        """

        if self.websites and self.scan_id == id(self.host):
            logs.logger.info(f'self.websites = {self.websites}')
            logs.logger.info('CONDITION SATISFIED! self.scan_id == id(self.host)')
            # if cache is not empty and we are still on the most recent scan
            return self.websites

        # refresh cache

        self.websites = []
        logs.logger.info('refresh cache## self.websites = []')

        target_ports = self.get_service_ports('http', 'tcp')
        logs.logger.info(target_ports)
        # target_ports += self.get_service_ports('https', 'tcp')

        for port in target_ports:

            try:

                request = urllib.request.urlopen('http://' + self.ip + ':' + str(port) + '/',
                                                 timeout=5)
                logs.logger.info(f'request : {request}')

                if request.headers.get_content_charset() is None:
                    content = request.read()
                    logs.logger.info(content)
                else:
                    content = request.read().decode(request.headers.get_content_charset())
                    logs.logger.info(content)

                self.websites.append(content)
                logs.logger.info(f'self.websites = {self.websites}')

            except Exception as e:
            	#logs.logger.error('Failed to fetch error for site!!!')
                if self.__debug:
                    logs.logger.info(f'self.__debug = {self.__debug}')
                    print('Failed to fetch homepage for site', self.ip, str(port), e)
                    logs.logger.error('Failed to fetch homepage for site!')
        logs.logger.info(f'self.websites = {self.websites}') 
        return self.websites

    def get_websites_css(self):
        """
        Gets website stylesheet for all active web servers found on the target
        :return: list of stylesheet strings
        """
        # TODO create a Website class containing stylesheet and others?

        if self.css and self.scan_id == id(self.host):
            logs.logger.info(f'self.css = {self.css}')
            logs.logger.info('CONDITION SATISFIED! self.scan_id == id(self.host)')
            # if cache is not empty and we are still on the most recent scan
            return self.css

        # refresh cache

        self.css = []
        logs.logger.info('refresh cache## self.css = []')

        target_ports = self.get_service_ports('http', 'tcp')
        logs.logger.info(f'target_ports = {target_ports}')
        # target_ports += self.get_service_ports('https', 'tcp')

        for port in target_ports:

            try:

                request = urllib.request.urlopen('http://' + self.ip + ':' + str(port) + '/style.css',
                                                 timeout=5)
                logs.logger.info(request)

                if request.headers.get_content_charset() is None:
                    content = request.read()
                    logs.logger.info(content)
                else:
                    content = request.read().decode(request.headers.get_content_charset())
                    logs.logger.info(content)

                self.css.append(content)

            except Exception as e:
                if self.__debug:
                    logs.logger.info(f'self.__debug = {self.__debug}')
                    print('Failed to fetch stylesheet for site', self.ip, str(port), e)
                    logs.logger.error('Failed to fetch stylesheet for site!!')
        logs.logger.info(self.css)
        return self.css


class ScanFailure(Exception):
    """Raised when one of the data gathering methods fails"""

    def __init__(self, *report):
        """
        :param report: description of the error
        """
        self.value = " ".join(str(r) for r in report)
        logs.logger.info(self.value)

    def __str__(self):
        return repr(self.value)

    def __repr__(self):
        return 'ScanFailure exception ' + self.value
