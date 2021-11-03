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

    async def status(self, request):
        return web.Response(text="running...")

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
        data = json.loads((await request.content.read()).decode())
        self.logger.info(f"deallocated {data}")


app = web.Application()
ts = TranscoderService()
app.add_routes([web.get('/status', ts.status),
                web.post('/allocate/transcoder', ts.allocate),
                web.post('/deallocate', ts.deallocate),
                web.get('/getState', ts.get_state)])
ts.logger.info(F"running with configuration {config}")
web.run_app(app, host=config.bind_ip_address, port=config.listen_port)
