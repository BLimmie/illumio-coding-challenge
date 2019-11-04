from firewall import *
import unittest

class TestMethods(unittest.TestCase):

    def test_ip(self):
        self.assertEqual(ip_to_int("1.1.1.1"), 0x01010101)
        self.assertEqual(ip_to_int("255.255.255.255"), 0xFFFFFFFF)

    def test_firewall_init_pre_rule_merge(self):
        firewall = Firewall("dev.csv", test_pre_merge=True)
        self.assertEqual(firewall.rules["inbound/tcp"], [Address(80,80,0xC0A80102,0xC0A80102)])
        self.assertEqual(firewall.rules["outbound/tcp"], [Address(10000,20000,0xC0A80A0B,0xC0A80A0B)])
        self.assertEqual(firewall.rules["inbound/udp"], [Address(53,53,0xC0A80101,0xC0A80205)])
        self.assertEqual(firewall.rules["outbound/udp"], [Address(1000,2000,ip_to_int("52.12.48.92"),ip_to_int("52.12.48.92"))])

    def test_merge(self):
        rules = [
            Address(1,3,10,10), 
            Address(2,4,9,11), 
            Address(1,4,2,3), 
            Address(3,3,3,10),
            Address(3,3,4,7),
            Address(4,4,4,7),
        ]
        merged = Address_rules(rules)
        self.assertEqual(merged[1], [Range(2,3), Range(10,10)])
        self.assertEqual(merged[2], [Range(2,3), Range(9,11)])
        self.assertEqual(merged[3], [Range(2,11)])
        self.assertEqual(merged[4], [Range(2,3), Range(4,7), Range(9,11)])

    def test_acceptance(self):
        fw = Firewall("dev.csv")
        self.assertTrue(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
        self.assertTrue(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"))
        self.assertTrue(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"))
        self.assertFalse(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
        self.assertFalse(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))
        
if __name__ == "__main__":
    unittest.main()