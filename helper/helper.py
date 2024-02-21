from threading import Thread, get_ident
from platform import system
from subprocess import Popen, PIPE
from socket import gethostbyaddr
from datetime import datetime
import re
ipv4 = re.compile("^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$")

class SubnetValidationError(Exception):
    pass

class InvalidCIDRFormat(SubnetValidationError):
    pass

class InvalidMask(SubnetValidationError):
    pass

class InvalidIP(SubnetValidationError):
    pass

def validateSubnet(subnet):
    try:
        ip, cidr = subnet.split("/")
    except Exception as e:
        raise InvalidCIDRFormat(f"Invalid notation, cannot identify IP and Netmask: {subnet}")
    try:
        cidr = int(cidr)
    except Exception as e:
        raise InvalidMask(f"The netmask must be a number, this is not: {cidr}")

    if (cidr < 1) or (cidr > 32):
        raise InvalidMask(f"The netmask is a value between 1 and 32!")
    if ipv4.match(ip):
        return True
    raise InvalidIP(f"This is not a valid IP: {ip}")
        
def validateIpv4(ip):
    return ipv4.match(ip)
        

class Collector(Thread):
    def __init__(self, jobqueue, resultqueue, logger):
        Thread.__init__(self)
        self.jobqueue = jobqueue
        self.resultqueue = resultqueue
        self.logger = logger

    def run(self):
        while True:
            current_task = self.jobqueue.get()
            dns_status = False
            ping_status = False
            self.logger.info(f"# {self.__class__.__name__} : ID : {get_ident()} :: Working on {current_task}")
            if system() == 'Windows':
                pinger = Popen(['ping',str(current_task)],stdout=PIPE)
            else:
                pinger = Popen(['ping','-c',"3",str(current_task)],stdout=PIPE)
            pingerOut, pingerErr = pinger.communicate()
            self.logger.info(f"# {self.__class__.__name__} : ID : {get_ident()} :: Return code was: {pinger.returncode}")
            if pinger.returncode == 0:
                ping_status = True
            self.logger.info(f"# {self.__class__.__name__} : ID : {get_ident()} :: Checking DNS...")
            try:
                dns_status = gethostbyaddr(str(current_task))
                self.logger.info(f"# {self.__class__.__name__} : ID : {get_ident()} :: DNS details: {dns_status}")
                dns_status = dns_status[0]
            except Exception as e:
                self.logger.info(f"# {self.__class__.__name__} : ID : {get_ident()} :: Failed to resolve DNS ({current_task}), because: {e}")
            self.resultqueue.put([current_task, ping_status,dns_status,datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
            self.resultqueue.task_done()            
            self.jobqueue.task_done()

