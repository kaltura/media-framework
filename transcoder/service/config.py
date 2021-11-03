import argparse
from service_utils import get_bind_ip_address


parser = argparse.ArgumentParser(description='')
parser.add_argument('--listen_port', dest='listen_port', type=int, action='store', default=80,  help="listen port")
parser.add_argument('--exe_path', dest='exe_path', type=str, action='store', default='',  help="a path to exe to spawn")
parser.add_argument('--die_url', dest='die_url', type=str, action='store', default=None,  help="url to send POST notification about death")
parser.add_argument('--bind_ip_address', dest='bind_ip_address', type=str, action='store', default=get_bind_ip_address(), help="specific ip address to bind transcoder enpoints to")
parser.add_argument('--log_files_dir', dest='log_files_dir', type=str, action='store', default=None,  help="directory to place logs")
parser.add_argument('--health_initial_timeout_sec', dest='health_initial_timeout_sec', type=int, action='store', default=10,  help="probe health of the new task after this many seconds")
parser.add_argument('--health_period_sec', dest='health_period_sec', type=int, action='store', default=None,  help="health check interval in seconds")
parser.add_argument('--max_concurrent_health_trasks', dest='max_concurrent_health_trasks', type=int, action='store', default=5,  help="max concurrently executing health checks")
parser.add_argument('--logging_level', dest='logging_level', type=str, action='store', default='debug',  help="log level")

config = parser.parse_args()

