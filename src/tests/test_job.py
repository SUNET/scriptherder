import sys
import logging
import unittest

from scriptherder import Job, Check

logging.basicConfig(level = logging.DEBUG, stream = sys.stderr,
                    format = '%(asctime)s: %(threadName)s %(levelname)s %(message)s')
logger = logging.getLogger('unittest')


class TestChecks(unittest.TestCase):

    def test_exit_status(self):
        """ Test executing 'echo test' """
        job = Job('echo_test', ['/bin/echo', 'test'])
        logger.debug('Job: {!r}'.format(job))
        logger.debug('As string: {!s}'.format(job))
        job.run()
        logger.debug('After run(): {!s}'.format(job))
        self.assertTrue(job.is_running)
        self.assertEqual(b'test\n', job.output)
        logger.debug('Start time: {!r}'.format(job.start_time))
        logger.debug('End   time: {!r}'.format(job.end_time))
        self.assertTrue(job.start_time <= job.end_time)
