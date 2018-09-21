import sys
import logging
import unittest

from scriptherder import Job, JobsList, Check, CheckStatus

logging.basicConfig(level = logging.DEBUG, stream = sys.stderr,
                    format = '%(asctime)s: %(threadName)s %(levelname)s %(message)s')
logger = logging.getLogger('unittest')


class TestCheckStatus(unittest.TestCase):

    check_ok = ''
    check_warn = ''
    runtime_mode = True

    @property
    def check(self):
        return Check(ok_str = self.check_ok,
                     warning_str = self.check_warn,
                     filename = 'unit_testing', logger = logger,
                     runtime_mode = self.runtime_mode)

    def test_two_failing_jobs(self):
        """ Test two failing jobs """
        checks = {}
        self.check_ok = 'exit_status=0, max_age=1m'
        self.check_warn = 'exit_status=0, max_age=5m'
        job1 = Job('test1', '/bin/true').run()
        job2 = Job('test1', '/bin/true').run()
        job1.check(self.check, logger)
        job2.check(self.check, logger)
        # back-date both jobs beyond warning
        _move_back(job1, 19 * 60)
        _move_back(job2, 20 * 60)
        self.runtime_mode = False
        checks['test1'] = self.check
        jobs = JobsList(None, logger, [job1, job2], load_not_running=False)
        cs = CheckStatus(None, logger, jobs=jobs, checks=checks)
        self.assertEqual(1, cs.num_jobs)
        self.assertEqual(('CRITICAL', 'age=19m>1m, age=19m>5m'), cs.aggregate_status())


def _move_back(job, seconds):
    job._data['start_time'] = job.start_time - seconds
    job._data['end_time'] = job.end_time - seconds
