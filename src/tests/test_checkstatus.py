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

    def test_two_delayed_jobs_critical(self):
        """ Test two failing jobs """
        checks = {}
        self.check_ok = 'exit_status=0, max_age=1m'
        self.check_warn = 'exit_status=0, max_age=5m'
        job1 = Job(name='test1', cmd=['/usr/bin/true'])
        job2 = Job(name='test1', cmd=['/usr/bin/true'])
        job1.run()
        job2.run()
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

    def test_positive_followed_by_negative_jobs(self):
        """ Real world scenario: Command runs successful, command fails """
        checks = {}
        self.check_ok = 'exit_status=0'
        self.check_warn = 'exit_status=0'
        job1 = Job(name='test1', cmd=['/usr/bin/true'])
        job2 = Job(name='test1', cmd=['/usr/bin/false'])
        job1.run()
        job2.run()
        job1.check(self.check, logger)
        job2.check(self.check, logger)
        self.runtime_mode = False
        checks['test1'] = self.check
        jobs = JobsList(None, logger, [job1, job2], load_not_running=False)
        cs = CheckStatus(None, logger, jobs=jobs, checks=checks)
        self.assertEqual(1, cs.num_jobs)
        self.assertEqual(('CRITICAL', 'stored_status=OK==False'), cs.aggregate_status())

    def test_job_failed_job(self):
        """Real world scenario:
        """
        checks = {}
        self.check_ok = 'exit_status=0,max_age=50m'
        self.check_warn = 'exit_status=0,max_age=1h'
        job1 = Job(name='test1', cmd=['/usr/bin/false'])
        job1.run()
        _move_back(job1, 10 )
        job1.check(self.check, logger)
        self.runtime_mode = False
        checks['test1'] = self.check
        jobs = JobsList(None, logger, [job1], load_not_running=False)
        cs = CheckStatus(None, logger, jobs=jobs, checks=checks)
        self.assertEqual(1, cs.num_jobs)
        self.assertEqual(('CRITICAL', 'stored_status=OK==False'), cs.aggregate_status())



def _move_back(job, seconds):
    job._data['start_time'] = job.start_time - seconds
    job._data['end_time'] = job.end_time - seconds
