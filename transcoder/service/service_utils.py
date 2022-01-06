import string
import random
import socket
import os
from aiohttp import ClientSession, ServerTimeoutError
import asyncio

pod_ip_addr = os.getenv('MY_POD_IP_ADDR')

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
                wait_interval = min(max_wait_interval_sec,wait_interval * exp)
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