"""
The Celery worker: made a fresh process before a prepared cell's tally, and its
memory watched while it tallies.

Restart
-------
The runbook's worker window runs its usual command inside a restart loop
(SERVER_RUNBOOK.md §4, window 1):

    while true; do uv run celery --app helios worker --events --beat --concurrency 1; sleep 2; done

restart() sends the worker a warm shutdown -- the broadcast `celery -A helios
control shutdown` sends, through the same app -- and waits until a worker with
a NEW pid answers `inspect ping`. The loop brings it back with the same
command, env and pinning, so the harness never decides how the worker is
started. Before a prepared tally the worker has had either N - S Celery
verifications (cast) or none (insert) since it last started; restarting in both
modes puts both on the same footing.

Memory
------
compute_tally loads every voter row at once (models.py:552), so the worker's
resident memory is what bounds N. MemoryProbe polls the RSS of the worker's
process tree -- the main process plus its children (the prefork pool child,
and the embedded beat) -- every 0.25 s, from a thread in the harness, and
reports the peak per stage. Operational: it bounds N, it is not a result.
"""

import threading
import time

import helios_env


def _app():
  helios_env.setup_django()
  from helios.celery_app import app
  return app


def workers(timeout=2.0):
  """{node: {'pid', 'pool'}} from `inspect stats`: the main pid and the pool
  children's pids of every worker that answers."""
  stats = _app().control.inspect(timeout=timeout).stats() or {}
  return {node: {'pid': s.get('pid'),
                 'pool': list((s.get('pool') or {}).get('processes') or [])}
          for node, s in stats.items()}


def ping(timeout=2.0):
  return _app().control.inspect(timeout=timeout).ping() or {}


def the_worker(timeout=2.0):
  """(node, info) of the one worker. The runbook runs exactly one
  (--concurrency 1); more than one means the tally could land on either."""
  found = workers(timeout)
  if len(found) != 1:
    raise RuntimeError(
      f'expected exactly one Celery worker, found {len(found)}'
      + (f': {", ".join(sorted(found))}' if found else
         '. Start it: SERVER_RUNBOOK.md §4, window 1'))
  return next(iter(found.items()))


def _identity(pid):
  """What must not change across a restart: the command line, the CPU
  affinity (Linux), and the HELIOS_MEASURE_PATH the worker records to."""
  import psutil
  p = psutil.Process(pid)
  env = {}
  try:
    env = p.environ()
  except (psutil.AccessDenied, psutil.ZombieProcess):
    pass
  return {
    'cmdline': p.cmdline(),
    'affinity': (sorted(p.cpu_affinity())
                 if hasattr(p, 'cpu_affinity') else None),
    'measure_path': env.get('HELIOS_MEASURE_PATH'),
  }


def restart(timeout_s=300, poll_s=0.5, log=print):
  """
  Warm-shut the worker down and wait for its replacement to answer ping.

  Returns {node, old_pid, new_pid, pool, seconds, identity}. Raises if no new
  worker answers within timeout_s -- the usual cause is a worker window
  started without the restart loop -- or if the new one is not started the way
  the old one was.
  """
  import psutil
  node, info = the_worker()
  old_pid = info['pid']
  before = _identity(old_pid)
  log(f'worker {node} pid {old_pid}: sending warm shutdown')

  t0 = time.perf_counter()
  _app().control.shutdown(destination=[node])

  deadline = time.perf_counter() + timeout_s
  while True:
    try:
      found = workers(timeout=1.0)
      answering = ping(timeout=1.0)
    except Exception:
      # The broker connection can drop while the old worker leaves.
      found, answering = {}, {}
    fresh = [(n, i) for n, i in found.items()
             if i['pid'] and i['pid'] != old_pid and n in answering]
    if len(found) == 1 and fresh and not psutil.pid_exists(old_pid):
      new_node, new_info = fresh[0]
      break
    if time.perf_counter() > deadline:
      raise TimeoutError(
        f'no fresh Celery worker answered within {timeout_s}s of shutting down '
        f'pid {old_pid}. The worker window must run the worker inside its '
        f'restart loop (SERVER_RUNBOOK.md §4, window 1); start it there, then '
        f'rerun the cell.')
    time.sleep(poll_s)
  seconds = time.perf_counter() - t0

  after = _identity(new_info['pid'])
  changed = [k for k in before if before[k] != after[k]]
  if changed:
    raise RuntimeError(
      f'the restarted worker differs from the one it replaced in '
      f'{", ".join(changed)}: before {before}, after {after}. The cell would '
      f'tally on a worker started differently.')
  log(f'fresh worker {new_node} pid {new_info["pid"]} answering after '
      f'{seconds:.1f} s')
  return {'node': new_node, 'old_pid': old_pid, 'new_pid': new_info['pid'],
          'pool': new_info['pool'], 'seconds': seconds, 'identity': after}


class MemoryProbe:
  """
  Peak RSS of the worker's process tree, per stage.

      probe = MemoryProbe(pid).start()
      probe.stage('aggregate'); ...; probe.stage('decrypt'); ...
      peaks = probe.stop()

  Samples only while a stage is set, and also on every stage change and at
  stop, so a stage shorter than one interval (a smoke-face tally) still has
  samples rather than a peak of zero. A child that exits between listing and
  reading is skipped; the main process vanishing is recorded, not fatal --
  the stage's own checks say whether the tally survived.
  """

  def __init__(self, pid, interval_s=0.25):
    self.pid = pid
    self.interval_s = interval_s
    self._label = None
    self._peaks = {}
    self._lock = threading.Lock()
    self._stop = threading.Event()
    self._thread = threading.Thread(target=self._run, daemon=True)

  def start(self):
    self._thread.start()
    return self

  def stage(self, label):
    self._record()                 # the end of the stage being left
    with self._lock:
      self._label = label
      self._peaks.setdefault(label, {'peak_tree_rss': 0, 'peak_main_rss': 0,
                                     'peak_child_rss': 0, 'max_processes': 0,
                                     'samples': 0, 'main_gone': False})
    self._record()                 # the start of the new one

  def stop(self):
    self._stop.set()
    self._thread.join(timeout=5)
    self._record()
    with self._lock:
      return {k: dict(v) for k, v in self._peaks.items()}

  def _sample(self):
    import psutil
    try:
      main = psutil.Process(self.pid)
      procs = [main] + main.children(recursive=True)
    except psutil.NoSuchProcess:
      return None
    rss = {}
    for p in procs:
      try:
        rss[p.pid] = p.memory_info().rss
      except (psutil.NoSuchProcess, psutil.ZombieProcess):
        pass
    return rss

  def _record(self):
    with self._lock:
      label = self._label
    if label is None:
      return
    rss = self._sample()
    with self._lock:
      pk = self._peaks[label]
      if rss is None or self.pid not in rss:
        pk['main_gone'] = True
        return
      pk['samples'] += 1
      pk['peak_tree_rss'] = max(pk['peak_tree_rss'], sum(rss.values()))
      pk['peak_main_rss'] = max(pk['peak_main_rss'], rss[self.pid])
      children = [v for k, v in rss.items() if k != self.pid]
      if children:
        pk['peak_child_rss'] = max(pk['peak_child_rss'], max(children))
      pk['max_processes'] = max(pk['max_processes'], len(rss))

  def _run(self):
    while not self._stop.is_set():
      self._record()
      self._stop.wait(self.interval_s)
