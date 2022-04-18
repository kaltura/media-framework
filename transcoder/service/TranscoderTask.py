import subprocess
import socket
import asyncio
from shutil import rmtree
import json
from config import config
from health import run_health_check_async
from service_utils import random_sequence, accept_connection, get_host_ip_address, pod_name
import os
from logger import create_logger
import signal

base_dir = os.getenv('BASE_DIR')

node_name = os.getenv('MY_NODE_NAME')

pod_ip_addr = get_host_ip_address()

class TaskEventsHandler:
    def task_exited(self, task):
        pass


class TranscoderTask:
    def __init__(self, handler: TaskEventsHandler, spec: dict):
        id = spec.get('act')
        spec["config"]['logger']['id'] = id
        self.handler = handler
        trans_id = f"{pod_name}:{spec.get('channelId')}:{spec.get('inputIndex')}{ 'v' if 0 == spec.get('trackType') else 'a'}@{'b' if spec.get('sessionType') else 'p'}:{id}"
        self.desc = {"id": trans_id,
                     "state": 2,
                     "clusterId": spec.get('inputClusterId'),
                     "nodeName": node_name,
                     "channelId": spec.get('channelId'),
                     "inputIndex": spec.get('inputIndex'),
                     "trackId": spec.get('trackId'),
                     "trackType": "Video" if 0 == spec.get('trackType') else "Audio",
                     "inputSessionType": spec.get('sessionType'),
                     "act": id,
                     **spec.get('required')}
        self.work_dir = os.path.join(base_dir, f"{self.id}")
        self.process = None
        self.logger = create_logger(f"{self.id} transcoder_session", "")
        os.mkdir(self.work_dir)
        self.logger.debug(f"TranscoderTask: {self.desc}")

    @property
    def id(self):
        return self.desc['id']

    async def run_health_loop(self):
        self.logger.debug(f"run_health_loop. sleeping  health_initial_timeout_sec {config.health_initial_timeout_sec}")
        await asyncio.sleep(config.health_initial_timeout_sec)
        while self.process and self.process.returncode is None:
            try:
                self.logger.info(f"about to check liveness")
                await run_health_check_async(self, False, config.health_period_sec * 3)
            except Exception as e:
                self.logger.error(f"liveness probe error {e}")
                self.process.kill()
                break
            else:
                self.logger.debug(f"run_health_loop. sleeping period: {config.health_period_sec}")
                await asyncio.sleep(config.health_period_sec)
        await run_health_check_async(self, True, config.health_period_sec)

    async def launch(self, session_config: dict):
        control = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        try:
            control.bind((pod_ip_addr, 0))
            # unfortunately it's not possible right now to pass inherited handle to ffmpeg http server:(
            control.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            control.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except:
            control.close()
            raise
        kmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        try:
            kmp.bind((pod_ip_addr, 0))
        except:
            control.close()
            kmp.close()
            raise
        addr, controlPort = control.getsockname()
        kmpPort = kmp.getsockname()[1]
        logPath = os.path.join(config.log_files_dir, f"{self.id}.log") if config.log_files_dir else None
        kmp.listen(1)
        self.desc["kmpPort"] = kmpPort
        self.desc["controlPort"] = controlPort
        session_config['control'] = {'listenPort': controlPort}
        self.desc["kmpHostName"] = addr
        self.desc["hostName"] = addr
        asyncio.create_task(self.wait_for_connection(kmp, control, logPath, session_config))
        return self.desc

    def cleanup(self):
        rmtree(self.work_dir, ignore_errors=True)

    async def wait_for_connection(self, kmp, control, logPath, session_config):
        try:
            self.logger.info(f"waiting for server to connect to: {kmp.getsockname()}")
            client, _ = await accept_connection(kmp,
                int(session_config.get('kmp', {}).get('acceptTimeout', 10)))
            client.setblocking(True)
            try:
                logFile = open(logPath, "w+") if logPath else None
                session_config['kmp'] = {'fd': client.fileno()}
                exe_args = ["-c", json.dumps(session_config)]
                self.logger.debug(
                    f"new client connected: {client.getsockname()} launching exe: {config.exe_path} {exe_args} \nlog: {logPath}")
                self.process = await asyncio.create_subprocess_exec(config.exe_path,
                                                                    *exe_args,
                                                                    stdin=subprocess.DEVNULL if logFile else None,
                                                                    stderr=subprocess.STDOUT if logFile else None,
                                                                    stdout=logFile if logFile else None,
                                                                    cwd=self.work_dir,
                                                                    pass_fds=[control.fileno(), client.fileno()])
                asyncio.create_task(self.watch_process_die())
            finally:
                client.close()
                if logFile:
                    logFile.close()
        except Exception as e:
            self.logger.error(f"wait_for_connection error: {e}. exiting now")
            self.handler.task_exited(self)
        finally:
            control.close()
            kmp.close()

    async def watch_process_die(self):
        asyncio.create_task(self.run_health_loop())
        await self.process.wait()
        self.cleanup()
        self.desc['errorCode'] = self.process.returncode
        self.logger.info(f" exited with status: {self.process.returncode}")
        self.handler.task_exited(self)

    async def suicide(self, timeout: int = 5) -> str:
        self.logger.info(f"commiting suicide with timeout: {timeout} sec")
        # schedule graceful exit
        self.process.send_signal(signal.SIGINT)
        try:
            await asyncio.wait_for(self.process.wait(), timeout=timeout)
        except:
            # brutally kill the process
            self.logger.warning(f" could not exit during given timeout; killing process")
            self.process.kill()
            await self.process.wait()
        return self.id

