from aiohttp import web
import asyncio
from logger import create_logger
import json
from service_utils import random_sequence, deallocate_task_with_retries
from config import config
from TranscoderTask import TranscoderTask, TaskEventsHandler


class TranscoderService(TaskEventsHandler):
    def __init__(self):
        super()
        self.tasks = {}
        self.logger = create_logger("transcoder_service", f"{config.bind_ip_address}:{config.listen_port}")

    async def allocate(self, request):
        data = (await request.content.read()).decode()
        self.logger.info(f"allocation request: {request} data: {data}")
        spec = json.loads(data)
        task = TranscoderTask(self, spec)
        responce = await task.launch(spec["config"])
        self.tasks[task.id] = task
        return web.json_response(body=json.dumps(responce))

    def task_exited(self, task: TranscoderTask):
        del self.tasks[task.id]
        asyncio.create_task(deallocate_task_with_retries(config.die_url,task.desc, 1, 1.1, self.logger))

    async def get_state(self, request):
        self.logger.debug(f"get_state")
        return web.json_response(body=json.dumps(list(map(lambda x: x.desc, self.tasks.values()))))

    async def deallocate(self, request):
        id = random_sequence(8)
        logger = create_logger(f"{id} deallocate ", "")
        data = json.loads((await request.content.read()).decode())
        logger.info(F"deallocate tasks {data}")
        processes = []
        killed = []
        if '*' in data:
            processes = list(map(lambda x: x.suicide(), self.tasks.values()))
        else:
            for pattern in map(lambda x: x.lower(), data):
              for id in filter(lambda x: pattern in x.lower(), self.tasks):
                 logger.info(F"found task {id}")
                 task = self.tasks[id]
                 processes.append(task.suicide())
        if processes:
            done, _ = await asyncio.wait(processes, timeout=5)
            killed = list(map(lambda x: x.result(), done))
            logger.info(f"tasks exited {killed}")
        else:
            logger.warn(f"no tasks found for input {data}")
        return web.json_response(body=json.dumps(killed))


app = web.Application()
ts = TranscoderService()
app.add_routes([web.get('/status', ts.get_state),
                web.post('/allocate/transcoder', ts.allocate),
                web.post('/deallocate', ts.deallocate)])
ts.logger.info(F"running with configuration {config}")
web.run_app(app, host=config.bind_ip_address, port=config.listen_port)
