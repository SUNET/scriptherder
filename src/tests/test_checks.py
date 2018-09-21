import sys
import logging
import unittest

from scriptherder import Job, Check

logging.basicConfig(level = logging.DEBUG, stream = sys.stderr,
                    format = '%(asctime)s: %(threadName)s %(levelname)s %(message)s')
logger = logging.getLogger('unittest')


class TestChecks(unittest.TestCase):

    def _run(self, cmd, ok='', warn='', run=True, runtime_mode = True):
        check = Check(ok, warn, 'unit_testing', logger, runtime_mode=True)
        self.job = Job('unittest_job', cmd)
        if run:
            self.job.run()
        self.job.check(check, logger)
        # Call status summary for all the tests to make sure it works in all
        # possible states
        logger.debug('Job status summary: {}'.format(self.job.status_summary()))
        if not runtime_mode:
            logger.info('Unit test evaluating checks again, post-execution')
            check = Check(ok, warn, 'unit_testing', logger, runtime_mode=False)
            self.job.check(check, logger)
            logger.debug('Job status summary: {}'.format(self.job.status_summary()))

    def test_exit_status_ok(self):
        """ Test exit status matching OK criteria """
        self._run(['/bin/echo', 'test'],
                  ok = 'exit_status=0')
        self.assertTrue(self.job.is_ok())

    def test_exit_status_warning(self):
        """ Test exit status matching WARN criteria """
        self._run(['/bin/echo', 'test'],
                  ok = 'exit_status=1', warn = 'exit_status=0')
        self.assertFalse(self.job.is_ok())
        self.assertTrue(self.job.is_warning())

    def test_exit_status_critical(self):
        """ Test exit status matching neither OK nor WARN criteria """
        self._run(['/bin/true', 'test'],
                  ok = 'exit_status=1', warn = 'exit_status=2')
        self.assertFalse(self.job.is_ok())
        self.assertFalse(self.job.is_warning())
        self.assertEqual(self.job.check_status, 'CRITICAL')

    def test_exit_status_negated1(self):
        """ Test exit status matching OK criteria (negated) """
        self._run(['/bin/false'],
                  ok = '!exit_status=0')
        self.assertTrue(self.job.is_ok())
        self.assertFalse(self.job.is_warning())

    def test_max_age(self):
        """ Test max_age criteria """
        self._run(['/bin/echo', 'test'],
                  ok = 'exit_status=0, max_age=10s', warn = 'exit_status=0, max_age=3h',
                  runtime_mode = False)
        self.assertTrue(self.job.is_ok())
        self.assertFalse(self.job.is_warning())

    def test_max_age_negated(self):
        """ Test max_age criteria (negated) """
        self._run(['/bin/echo', 'test'],
                  ok = 'exit_status=0, !max_age=10s', warn = 'exit_status=0, max_age=3h',
                  runtime_mode = False)
        self.assertFalse(self.job.is_ok())
        self.assertTrue(self.job.is_warning())

    def test_file_exists(self):
        """ Test file_exists criteria """
        self._run(['/bin/echo', 'test'],
                  ok = 'exit_status=1', warn = 'exit_status=1,OR_file_exists=/etc/services',
                  runtime_mode = False)
        self.assertFalse(self.job.is_ok())
        self.assertTrue(self.job.is_warning())

    def test_file_exists_negated(self):
        """ Test file_exists criteria (negated) """
        self._run(['/bin/false'],
                  ok = 'exit_status=0,!OR_file_exists=/this_could_be_a_FAIL_file',
                  runtime_mode = False)
        self.assertTrue(self.job.is_ok())

    def test_file_exists_fail(self):
        """ Test file_exists criteria failure """
        self._run(['/bin/false'],
                  ok = 'exit_status=0,OR_file_exists=/this_file_should_not_exist',
                  runtime_mode = False)
        self.assertFalse(self.job.is_ok())
        self.assertEqual(self.job.check_status, 'CRITICAL')
        self.assertEqual(self.job.check_reason,
                         'file_does_not_exist=/this_file_should_not_exist, stored_status=OK==False')

    def test_OR_running(self):
        """ Test OR_running criteria """
        self._run(['/bin/echo', 'test'],
                  ok = 'exit_status=1,OR_running', warn = 'exit_status=0')
        self.assertTrue(self.job.is_ok())
        self.assertFalse(self.job.is_warning())

    def test_OR_running_negated(self):
        """ Test OR_running criteria """
        self._run(['/bin/echo', 'test'],
                  ok = 'exit_status=1,OR_running', warn = '!OR_running',
                  run = False)
        self.assertFalse(self.job.is_ok())
        self.assertTrue(self.job.is_warning())

    def test_output_contains(self):
        """ Test output_contains criteria """
        self._run(['/bin/echo', 'STATUS_TESTING_OK'],
                  ok = 'exit_status=0,output_contains=TESTING')
        self.assertTrue(self.job.is_ok())
        self.assertEqual(self.job.check_reason, 'exit=0, output_contains=TESTING==True')

    def test_output_contains_negated(self):
        """ Test output_contains criteria (negated) """
        self._run(['/bin/echo', 'STATUS_TESTING_OK'],
                  ok = 'exit_status=0,!output_contains=ERROR')
        self.assertTrue(self.job.is_ok())
        self.assertEqual(self.job.check_reason, 'exit=0, !output_contains=ERROR==True')

    def test_obsolete_output_not_contains(self):
        """ Test obsolete option output_not_contains """
        self._run(['/bin/echo', 'STATUS_TESTING_OK'],
                  ok = 'exit_status=0,output_not_contains=ERROR')
        self.assertTrue(self.job.is_ok())
        self.assertEqual(self.job.check_reason, 'exit=0, !output_contains=ERROR==True')

    def test_output_matches(self):
        """ Test output_matches criteria """
        self._run(['/bin/echo', 'STATUS_TESTING_OK'],
                  ok = 'exit_status=0,output_matches=.*TESTING.*')
        self.assertTrue(self.job.is_ok())
        self.assertEqual(self.job.check_reason, 'exit=0, output_matches=.*TESTING.*==True')

    def test_output_matches_negated(self):
        """ Test output_matches criteria (negated) """
        self._run(['/bin/echo', 'STATUS_TESTING_OK'],
                  ok = 'exit_status=0,!output_matches=.*ERROR.*')
        self.assertTrue(self.job.is_ok())
        self.assertEqual(self.job.check_reason, 'exit=0, !output_matches=.*ERROR.*==True')
