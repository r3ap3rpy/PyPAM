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
        
