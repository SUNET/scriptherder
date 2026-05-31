"""
Baseline tests derived from real job statuses observed on a host running
scriptherder-wrapped cronjobs.
"""

import sys
import time
import logging
import unittest

from scriptherder import Job, Check

logging.basicConfig(level=logging.DEBUG, stream=sys.stderr,
                    format='%(asctime)s: %(threadName)s %(levelname)s %(message)s')
logger = logging.getLogger('unittest')


def _make_job(name, age_seconds, exit_status, check_status=None):
    """Return a Job constructed from a data dict (no actual execution)."""
    now = time.time()
    data = {
        'cmd': ['/usr/local/bin/job.sh'],
        'exit_status': exit_status,
        'name': name,
        'pid': 12345,
        'start_time': now - age_seconds - 10,
        'end_time': now - age_seconds,
        'output_size': 0,
        'version': 2,
    }
    if check_status is not None:
        data['check_status'] = check_status
        data['check_reason'] = 'exit=0'
    return Job(name, data=data)


def _check(ok_str, warn_str):
    return Check(ok_str=ok_str, warning_str=warn_str,
                 filename='unit_testing', logger=logger,
                 runtime_mode=False)


class TestModeCheck(unittest.TestCase):

    def test_cosmos_ok(self):
        """cosmos ran 9 minutes ago with check_status=OK → OK"""
        job = _make_job('cosmos', age_seconds=9 * 60, exit_status=0, check_status='OK')
        job.check(_check('exit_status=0, max_age=90m',
                         'exit_status=0, max_age=24h'), logger)
        self.assertTrue(job.is_ok())

    def test_backup_daily_ok(self):
        """backup_daily ran 30 hours ago (well within 50h ok threshold) with check_status=OK → OK"""
        job = _make_job('backup_daily', age_seconds=30 * 3600, exit_status=0, check_status='OK')
        job.check(_check('exit_status=0, max_age=50h',
                         'exit_status=0, max_age=72h'), logger)
        self.assertTrue(job.is_ok())
