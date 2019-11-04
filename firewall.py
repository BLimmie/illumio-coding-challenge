import csv
import re

RANGE_PATTERN = r'(.*)?-(.*)'
IP_PATTERN = r'(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})'

def ip_to_int(ip):
    """
    Converts string ip address to an int64
    """
    match = re.fullmatch(IP_PATTERN, ip)
    if match is None:
        raise SyntaxError

    ip_as_int = 0
    for i in range(1,5):
        ip_as_int = ip_as_int*256 + int(match.group(i))

    return ip_as_int

def binary_search(ranges, x):
    """
    Binary search for existence of value $x in list of Range $ranges 
    """
    l,r = 0, len(ranges)-1
    while l <= r:
        mid = (l+r)//2
        if ranges[mid].contains(x):
            return True
        elif ranges[mid] < x:
            l = mid+1
        elif ranges[mid] > x:
            h = mid-1
    return False

class Address:
    """
    Temporary storage class for ip addresses and ports
    """
    def __init__(self, min_port, max_port, min_ip, max_ip):
        self.min_port = min_port
        self.max_port = max_port
        self.min_ip = min_ip
        self.max_ip = max_ip
    
    def __eq__(self, other):
        if type(self) != type(other):
            return False
        if self.min_ip != other.min_ip:
            return False
        if self.max_ip != other.max_ip:
            return False
        if self.min_ip != other.min_ip:
            return False
        if self.max_ip != other.max_ip:
            return False
        return True

class Address_rules:
    """
    Takes a list of Address objects and merges them together to form a list of rules

    Stores these rules and allows indexing as if it were a dictionary where keys are port numbers
    """
    def __init__(self, rules):
        self.rules = [[] for i in range(65336)]
        for address in rules:
            address_range = Range(address.min_ip,address.max_ip)
            for i in range(address.min_port, address.max_port+1):
                ranges = self.rules[i]
                inserted = False
                for j in range(len(ranges)):
                    r1 = ranges[j]
                    #r1 contains max ip, doesn't need to propagate
                    if r1.contains(address.max_ip):
                        r1.min = min(r1.min, address.min_ip)
                        inserted = True
                        break
                    #address range contains r1 max
                    if address_range.contains(r1.max):
                        r1.min = min(address_range.min, r1.min)
                        r1.max = address_range.max
                        to_remove = []
                        #propagate merges to potentially greater ranges and stops when it can't be merged
                        for k in range(j+1,len(ranges)):
                            r2 = ranges[k]
                            if r1.contains(r2.min) and r1.contains(r2.max):
                                to_remove.insert(0,k)
                                continue
                            if r2.contains(r1.max):
                                r1.max = r2.max
                                to_remove.insert(0,k)
                                break
                        for idx in to_remove:
                            ranges.pop(idx)
                        inserted = True
                        break
                # If no merges occurred, find where the range belongs in the list sorted in asc order
                if not inserted:
                    for j in range(len(ranges)):
                        if ranges[j].min > address.min_ip:
                            ranges.insert(j, Range(address.min_ip, address.max_ip))
                            inserted = True
                            break
                    if not inserted:
                        ranges.append(Range(address.min_ip, address.max_ip))
    def __getitem__(self, key):
        return self.rules[key]

                

class Range:
    """
    Container for range of numbers
    can check if value is less than, in, or greater than a range
    """
    def __init__(self, min_, max_):
        self.min = min_
        self.max = max_

    def contains(self, val):
        return val <= self.max and val >= self.min

    def __eq__(self, other):
        if type(other) != type(self):
            return False
        return self.min == other.min and self.max == other.max

    def __repr__(self):
        return "{}-{}".format(self.min, self.max)

    def __lt__(self, val):
        return val > self.max
    
    def __gt__(self, val):
        return val < self.min

class Firewall:
    def __init__(self, csvfile, test_pre_merge=False):
        self.rules = {
            "inbound/tcp":[],
            "outbound/tcp":[],
            "inbound/udp":[],
            "outbound/udp":[]
        }
        with open(csvfile) as f:
            reader = csv.reader(f)
            for row in reader:
                direction = row[0]
                protocol = row[1]
                ports = row[2]
                addresses = row[3]
                ports_match = re.fullmatch(RANGE_PATTERN, ports)
                add_match = re.fullmatch(RANGE_PATTERN, addresses)
                if ports_match is not None:
                    min_port = int(ports_match.group(1))
                    max_port = int(ports_match.group(2))
                else:
                    # not a range
                    min_port = int(ports)
                    max_port = min_port

                if add_match is not None:
                    min_address = ip_to_int(add_match.group(1))
                    max_address = ip_to_int(add_match.group(2))
                else:
                    # not a range
                    min_address = ip_to_int(addresses)
                    max_address = min_address
                key = "/".join([direction,protocol])
                self.rules[key].append(Address(min_port,max_port,min_address,max_address))

        # for unit test to check if addresses got read correctly
        if test_pre_merge:
            return

        for key in self.rules:
            self.rules[key] = Address_rules(self.rules[key])
        
    def accept_packet(self, direction, protocol, port, ip_address):
        key = "/".join((direction, protocol))
        rules = self.rules[key]
        ranges = rules[port]
        return binary_search(ranges, ip_to_int(ip_address))
