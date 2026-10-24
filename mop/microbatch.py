"""Coalesce independent requests; retain one Future and one verdict per operation."""
import asyncio
import copy
import math
import time
from collections import Counter,deque

from .core import percentile, Verdict


class MicroBatchProvider:
    def __init__(self,transport,batch_size=4,batch_wait_ms=1,max_batches=2,pending_capacity=256):
        if type(batch_size) is not int or not 1<=batch_size<=64:
            raise ValueError("batch_size must be 1..64")
        if not math.isfinite(batch_wait_ms) or not 0<=batch_wait_ms<=50:
            raise ValueError("batch_wait_ms must be 0..50")
        if max_batches<1 or pending_capacity<1:
            raise ValueError("batch concurrency and pending capacity must be positive")
        self.transport=transport
        self.name=transport.name
        self.labels=getattr(transport,"labels",())
        self.model=getattr(transport,"model","")
        self.batch_size,self.batch_wait_ms=batch_size,batch_wait_ms
        self.max_batches=max_batches
        self.pending=asyncio.Queue(pending_capacity)
        self.slots=asyncio.Semaphore(max_batches)
        self.dispatcher=None
        self.active=set()
        self.closed=False
        self.stats=Counter()
        self.histogram=Counter()
        self.waits=deque(maxlen=4096)
        self.service_times=deque(maxlen=4096)

    async def infer(self,event):
        if self.closed:raise RuntimeError("batch provider closed")
        if self.dispatcher is None:
            self.dispatcher=asyncio.create_task(self._dispatch())
        event=copy.deepcopy(event)
        future=asyncio.get_running_loop().create_future()
        try:self.pending.put_nowait((event,future,time.monotonic()))
        except asyncio.QueueFull:
            self.stats["rejected_pending_full"]+=1
            raise RuntimeError("batch pending queue full") from None
        self.stats["submitted"]+=1
        self.stats["peak_pending"]=max(self.stats["peak_pending"],self.pending.qsize())
        return await future

    async def _dispatch(self):
        acquired=False
        owned=[]
        try:
            while True:
                await self.slots.acquire();acquired=True
                first=await self.pending.get()
                owned=[first]
                # Yield once to coalesce arrivals from the same event-loop tick.
                await asyncio.sleep(0)
                deadline=first[2]+self.batch_wait_ms/1000
                while len(owned)<self.batch_size:
                    try:item=self.pending.get_nowait()
                    except asyncio.QueueEmpty:
                        remaining=deadline-time.monotonic()
                        if remaining<=0:break
                        try:item=await asyncio.wait_for(self.pending.get(),remaining)
                        except asyncio.TimeoutError:break
                    owned.append(item)
                items=[item for item in owned if not item[1].cancelled()]
                for item in owned:
                    self.pending.task_done()
                    if item[1].cancelled():self.stats["cancelled_before_dispatch"]+=1
                owned=[]
                if not items:
                    self.slots.release();acquired=False
                    continue
                task=asyncio.create_task(self._send(items))
                self.active.add(task)
                task.add_done_callback(self.active.discard)
                acquired=False
        finally:
            if acquired:self.slots.release()
            for _,future,_ in owned:
                if not future.done():future.cancel()
                self.pending.task_done()

    async def _send(self,items):
        started=time.monotonic()
        self.stats["active_batches"]+=1
        self.stats["peak_active_batches"]=max(self.stats["peak_active_batches"],self.stats["active_batches"])
        self.stats["batches"]+=1
        self.histogram[len(items)]+=1
        try:
            try:
                verdicts=await self.transport.infer_batch([item[0] for item in items])
            except ValueError as error:
                if len(items)<2 or str(error)!='model HTTP status 400':raise
                # A rejected input must not erase independent decisions in its batch.
                # Retry sequentially inside the existing concurrency slot.
                self.stats['isolated_rejected_batches']+=1
                verdicts=[]
                for event,_,_ in items:
                    try:verdicts.append((await self.transport.infer_batch([event]))[0])
                    except Exception as failure:
                        self.stats['isolated_failed_inputs']+=1
                        verdicts.append(Verdict('unknown','Individual input failed: '+type(failure).__name__,self.name))
            if len(verdicts)!=len(items):
                raise ValueError("batch verdict count mismatch")
            if any(not isinstance(verdict,Verdict) for verdict in verdicts):
                raise ValueError('invalid batch verdict')
            verdicts=[copy.deepcopy(verdict) for verdict in verdicts]
            for (_,future,queued),verdict in zip(items,verdicts):
                waiting=(started-queued)*1000
                self.waits.append(waiting)
                verdict.timing["batch_wait_ms"]=waiting
                if not future.done():future.set_result(verdict)
            self.stats["completed_decisions"]+=len(items)
        except asyncio.CancelledError:
            for _,future,_ in items:
                if not future.done():future.cancel()
            raise
        except Exception as error:
            self.stats["failed_decisions"]+=len(items)
            for _,future,_ in items:
                if not future.done():future.set_exception(error)
        finally:
            self.service_times.append((time.monotonic()-started)*1000)
            self.stats["active_batches"]-=1
            self.slots.release()

    async def aclose(self):
        if self.closed:return
        self.closed=True
        if self.dispatcher:
            self.dispatcher.cancel()
            await asyncio.gather(self.dispatcher,return_exceptions=True)
        for task in list(self.active):task.cancel()
        await asyncio.gather(*list(self.active),return_exceptions=True)
        while not self.pending.empty():
            _,future,_=self.pending.get_nowait()
            if not future.done():future.cancel()
            self.pending.task_done()

        if hasattr(self.transport,"aclose"):
            await self.transport.aclose()

    def summary(self):
        return {**dict(self.stats),"batch_size_limit":self.batch_size,
                "batch_wait_limit_ms":self.batch_wait_ms,"max_batches":self.max_batches,
                "pending":self.pending.qsize(),"batch_histogram":dict(self.histogram),
                "batch_wait_p95_ms":percentile(self.waits,.95),
                "batch_service_p95_ms":percentile(self.service_times,.95),
                "mean_batch_fill":sum(size*count for size,count in self.histogram.items())/max(1,self.stats["batches"]*self.batch_size),
                "transport":self.transport.summary()}
