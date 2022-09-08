import os
import gzip
import TranscoderTask
import asyncio
import concurrent.futures
from psutil import cpu_count
from config import config

#try:
from utils import read_file, insert_to_redis, delete_state_from_redis
#except:
    #def read_file(*args):
        #return None
    #def insert_to_redis(*args):
        #pass

# limit number of concurrent health checks to number of available processors x 5
# because part of the code is I/O bound while zip is CPU bound we can concurrently execute as many
executor = concurrent.futures.ProcessPoolExecutor(
    max_workers=cpu_count(logical=False) * config.max_concurrent_health_tasks
)

def run_health_check(id: str, p: str):
    state = read_file(os.path.join(p, "lastState.json"))
    if state:
        compressedState = gzip.compress(state)
        a = insert_to_redis("transcoder", compressedState, pod_name_override=id)
        print(a)
    else:
        print(f"state for {id} not found")


async def run_health_check_async(transcoder: TranscoderTask, delete: bool, timeout: int = None):
    loop = asyncio.get_event_loop()
    if delete:
        health_task = loop.run_in_executor(executor, delete_state_from_redis, "transcoder", transcoder.id)
    else:
        health_task = loop.run_in_executor(executor, run_health_check, transcoder.id, transcoder.work_dir)
    completed, pending = await asyncio.wait([health_task], timeout=timeout)
    if pending:
        pending.pop().cancel()
        raise TimeoutError()
    return completed.pop().result()
