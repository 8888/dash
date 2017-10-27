'''
Basic ARP listener
Credit to: https://blog.cloudstitch.com/how-i-hacked-amazon-s-5-wifi-button-to-track-baby-data-794214b0bdd8
'''

from scapy.all import *
from datetime import datetime

BUTTONS = {
    'oats': {'name': 'Oats', 'mac': '18:74:2e:03:9a:ac'},
    'chocolate': {'name': 'Chocolate', 'mac': '78:e1:03:4c:d8:5d'}
}

def filter_arp(pkt):
    if pkt[ARP].op == 1: #who-has (request)
        for key, button in BUTTONS.iteritems():
            if pkt[ARP].hwsrc == button['mac']:
                output_button(button)

def output_button(button):
    now = datetime.now().time()
    print "Pressed the {} button at {}".format(button['name'], now)

def main():
    sniff(prn=filter_arp, filter="arp", store=0)

if __name__ == "__main__":
    main()
