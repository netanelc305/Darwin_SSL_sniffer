import logging

import click
import coloredlogs
import rpcclient.protocol
from pymobiledevice3.cli.cli_common import Command, LockdownCommand
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.lockdown_service_provider import LockdownServiceProvider
from rpcclient.client_factory import create_client

from darwin_ssl_sniffer.sniffer import Filters, HostSniffer, MobileSniffer

GLOBAL_PREFERENCE = '/private/var/Managed Preferences/mobile/.GlobalPreferences.plist'
CFNETWORK_KEY = 'AppleCFNetworkDiagnosticLogging'

coloredlogs.install(level=logging.INFO)
logger = logging.getLogger(__name__)


def default_none(ctx, _, value):
    if len(value) == 0:
        return None
    else:
        return value


@click.group()
def cli():
    pass


@cli.group()
def mobile():
    pass


@mobile.command('setup', cls=LockdownCommand)
@click.option('-p', '--port', type=click.INT, default=rpcclient.protocol.DEFAULT_PORT, help='rpc server ip and port')
def cli_setup(service_provider: LockdownClient, port):
    """ Setup all prerequisites required inorder to sniff the SSL traffic """

    def usbmux_connect():
        return service_provider.service.mux_device.connect(port)

    rpc = create_client(usbmux_connect)

    with rpc.preferences.sc.open(GLOBAL_PREFERENCE) as global_preferences:
        if not global_preferences.get(CFNETWORK_KEY):
            global_preferences.set(CFNETWORK_KEY, 3)
            logger.info(f'{CFNETWORK_KEY} is now set, a restart is required')
            return
    logger.info(f'{CFNETWORK_KEY} already set')
    rpc.syslog.set_harlogger_for_all(True)


@mobile.command('sniff', cls=Command)
@click.option('out_file', '-o', '--out', default='traffic.pcapng', type=click.Path(),
              help='outfile name with .pcapng extension')
@click.option('pids', '-p', '--pid', type=click.INT, multiple=True, callback=default_none, help='filter pid list')
@click.option('process_names', '-pn', '--process-name', callback=default_none, multiple=True,
              help='filter process name list')
@click.option('images', '-i', '--image', multiple=True, callback=default_none, help='filter image list')
@click.option('--black-list/--white-list', default=True, is_flag=True)
def cli_mobile_sniff(service_provider: LockdownServiceProvider, pids, process_names, images, out_file, black_list):
    """ Sniff the traffic """

    filters = Filters(pids, process_names, images, black_list)
    MobileSniffer(service_provider, out_file, filters=filters).sniff()


@cli.command('sniff')
@click.option('out_file', '-o', '--out', default='traffic.pcapng', type=click.Path(),
              help='outfile name with .pcapng extension')
@click.option('pids', '-p', '--pid', type=click.INT, multiple=True, callback=default_none, help='filter pid list')
@click.option('process_names', '-pn', '--process-name', callback=default_none, multiple=True,
              help='filter process name list')
@click.option('images', '-i', '--image', multiple=True, callback=default_none, help='filter image list')
@click.option('--black-list/--white-list', default=True, is_flag=True)
def cli_sniff(out_file: str, pids, process_names, images, black_list):
    """ Sniff the traffic """

    filters = Filters(pids, process_names, images, black_list)
    HostSniffer(out_file, filters=filters).sniff()


if __name__ == '__main__':
    cli()
