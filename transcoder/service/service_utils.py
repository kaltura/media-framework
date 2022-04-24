import math
import string
import random
import socket
import os
from aiohttp import ClientSession, ServerTimeoutError
import asyncio

pod_ip_addr = os.getenv('MY_POD_IP_ADDR')

pod_name = os.getenv('MY_POD_NAME')

prom_metric_prefix = os.getenv('PROM_METRIC_PREFIX')

prom_component_label = os.getenv('PROM_METRIC_COMPONENT_LABEL')


# get preferred ip address visible by others
def get_host_ip_address():
    listen_address = pod_ip_addr
    if not listen_address:
        try:
            listen_address = socket.gethostbyname(socket.gethostname())
        except socket.gaierror as e:
            print(f"gethostbyname(socket.gethostname()) failed: {e} falling back on local")
            listen_address = '127.0.0.1'
    return listen_address

def random_sequence(n: int):
    return ''.join(random.choice(string.hexdigits) for i in range(n))

async def deallocate_task_with_retries(die_url: str,data: dict,wait_interval:float,exp:float,logger,max_wait_interval_sec:float=50):
    if exp <= 0:
        raise Exception('invalid backoff factor provided')
    id = random_sequence(4)
    logger.info(f"deallocate_task_with_retries({id}): report: {data} wait_interval: {wait_interval} exp: {exp} max_wait_interval_sec: {max_wait_interval_sec}")
    while True:
        async with ClientSession() as session:
            try:
                await session.post(die_url, json=data)
                logger.info(f"deallocate_task_with_retries({id}): success")
                break
            except ServerTimeoutError as ex:
                logger.error(f"deallocate_task_with_retries({id}): error: {ex} wait: {wait_interval}")
                await asyncio.sleep(wait_interval)
                wait_interval = min(max_wait_interval_sec, wait_interval * exp)
            except Exception as ex:
                logger.error(f"deallocate_task_with_retries({id}): error: {ex}")
                break

#workaround for lousy python 3.8 asyncio.sock_accept which blocks the thread
async def accept_connection(kmp: socket,timeout):
    loop = asyncio.get_event_loop()
    fut = loop.create_future()
    def handle_accept():
        fut.set_result(kmp.accept())
    loop.add_reader(kmp.fileno(),handle_accept)
    try:
        return await asyncio.wait_for(fut, timeout)
    finally:
        loop.remove_reader(kmp.fileno())

def generate_metrics(state) -> str:
    # TODO: replace hardcoded list of metrics with something configurable
    metrics = {'kaltura.com/gpu_encoder_score': 0,
               'kaltura.com/gpu_decoder_score': 0,
               'kaltura.com/cpu': 0}
    def format_num(n, m = 3) -> str:
        return format(n, F".{m}f")
    metric_prefix = 'kaltura.com/'
    if state:
        for transtate in state:
            for k in filter(lambda k: k.startswith(metric_prefix), transtate):
                if k not in metrics:
                    metrics[k] = transtate[k]
                else:
                    metrics[k] += transtate[k]
    offset = len(metric_prefix)
    out = ''
    for k, v in metrics.items():
        metric_p = prom_metric_prefix + k[offset:]
        # out += f"# HELP {metric_p} Metric read from /metrics-prometheus/.prom\n# TYPE {metric_p} UNTYPED\n"
        out += "{0}{{component=\"{1}\",kubernetes_pod_name=\"{2}\"}} {3}\n".format(metric_p, prom_component_label,
                                                                                 pod_name, format_num(v))
    # convenience metrics
    if len(metrics):
        out += '{0}max{{component=\"{1}\",kubernetes_pod_name=\"{2}\"}} {3}\n'.format(prom_metric_prefix,
                                                                                    prom_component_label, pod_name,
                                                                                    format_num(max(metrics.values())))
        out += '{0}avg{{component=\"{1}\",kubernetes_pod_name=\"{2}\"}} {3}\n'.format(prom_metric_prefix,
                                                                                    prom_component_label, pod_name,
                                                                                    format_num(
                                                                                        sum(metrics.values()) / len(
                                                                                            metrics)))
        out += '{0}total{{component=\"{1}\",kubernetes_pod_name=\"{2}\"}} {3}\n'.format(prom_metric_prefix,
                                                                                      prom_component_label, pod_name,
                                                                                      format_num(sum(metrics.values())))
        out += '{0}scalar{{component=\"{1}\",kubernetes_pod_name=\"{2}\"}} {3}\n'.format(prom_metric_prefix,
                                                                                      prom_component_label, pod_name,
                                                                                      format_num(math.sqrt(sum(map(lambda x: x*x, metrics.values())))))
    return out
