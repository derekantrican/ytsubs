import os
import queue
import threading
import time


to_process = queue.SimpleQueue()
was_processed = queue.SimpleQueue()


def add_task(q, *args, attempt=None, **kwargs):
    forced = dict(
        attempt=attempt or 1,
        retry_backoff=kwargs.get('retry_backoff'),
    )
    if float(forced['retry_backoff'] or float()) < 1.1:
        forced['retry_backoff'] = 1.1
    task = dict(
        retries=3,
        retry_delay=0.2,
        retry_backoff=2.25,
    )
    task.update(kwargs, **forced)
    return q.put(task)


def run_task(q_in, q_out, func, /):
    empties = 0
    while empties < 9:
        try:
            task = q_in.get(timeout=0.1)
            empties = 0
            try:
                q_out.put( func(task) )
            except Exception:
                attempt = task.get('attempt') or 1
                attempt += 1
                retries = task.get('retries') or 0
                retry_delay = task.get('retry_delay') or 0.1
                retry_backoff = task.get('retry_backoff') or 1.1
                if retries:
                    retries -= 1
                    task['retries'] = retries
                    task['retry_delay'] = retry_delay * retry_backoff
                    time.sleep(retry_delay)
                    add_task(q_in, attempt=attempt, **task)
        except queue.Empty:
            empties += 1


def start_workers(number=None, *, func=dict):
    if number is None:
        cpus = len(os.sched_getaffinity(0))
        number = (cpus or 4) // 2
    n = max(1, int(number))
    while n > 0:
        n -= 1
        threading.Thread(
            daemon=False,
            target=run_task,
            args=(
                to_process,
                was_processed,
                func,
            ),
        ).start()
