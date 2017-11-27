#!/usr/bin/env python
#
# Copyright 2014, 2015, 2017 SUNET. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
#    1. Redistributions of source code must retain the above copyright notice, this list of
#       conditions and the following disclaimer.
#
#    2. Redistributions in binary form must reproduce the above copyright notice, this list
#       of conditions and the following disclaimer in the documentation and/or other materials
#       provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY SUNET ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL SUNET OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those of the
# authors and should not be interpreted as representing official policies, either expressed
# or implied, of SUNET.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#

"""
The basic idea with Scriptherder is to run e.g. cronjobs and save metadata about the
execution better than sending e-mails to root that never gets read.

While we're at it, we save more than just the output (time, exit status, ...) which
it is then possible to use to monitor that jobs are working.

Scriptherder can be run in one othe following modes:

   wrap        -- Stores output, exit status etc. about a script invocation
   ls          -- Lists the logged script invocations
   check       -- Check if script execution results match given criterias,
                  output Nagios compatible result
   lastlog     -- Show last execution output of a job (or all jobs)
   lastfaillog -- Show last failed execution output of a job (or all jobs)

The 'check' mode compares job status against criterias in INI-files (in checkdir, default
/etc/scriptherder/check) and produces Nagios compatible output.


Example check file contents for job that is OK if it exited 0 and was last run less
than eight hours ago, WARNING if less than 24 and after that CRITICAL:

    [check]
    ok = exit_status=0, max_age=8h
    warning = exit_status=0, max_age=24h

 All criterias:

    exit_status=0                Must exit(0)
    max_age=8h                   Must have executed less than 8h ago
    not_running                  Job is not running
    output_contains=OK           Output contains the text OK
    output_matches=.*OK.*        Output matches the regexp
    OR_file_exists=FILE          Check if a file exists, such as a disable-file for a job
    OR_running                   True if a job is running - useful for jobs that run @reboot etc.
"""

import os
import re
import six
import sys
import shutil
import time
import json
import logging
import logging.handlers
import argparse
import subprocess
from six.moves import configparser

_defaults = {'debug': False,
             'syslog': False,
             'mode': 'ls',
             'datadir': '/var/cache/scriptherder',
             'checkdir': '/etc/scriptherder/check',
             }

_check_defaults = {'ok': 'exit_status=0,max_age=8h',
                   'warning': 'exit_status=0,max_age=24h',
                   }

exit_status = {'OK': 0,
               'WARNING': 1,
               'CRITICAL': 2,
               'UNKNOWN': 3,
               }


class ScriptHerderError(Exception):
    """
    Base exception class for scriptherder.
    """

    def __init__(self, reason, filename):
        self.reason = reason
        self.filename = filename


class JobLoadError(ScriptHerderError):
    """
    Raised when loading a job file fails.
    """


class CheckLoadError(ScriptHerderError):
    """
    Raised when loading a check file fails.
    """


class Job(object):
    """
    Representation of an execution of a job.
    """

    def __init__(self, name, cmd=None, data=None):
        if cmd is None:
            cmd = []
        for x in cmd:
            assert(isinstance(x, six.string_types))
        if data is None:
            data = {'version': 2,
                    'name': name,
                    'cmd': cmd,
                    }
        if data.get('name') is None:
            data['name'] = os.path.basename(cmd[0])

        if data.get('version') not in [1, 2]:
            raise JobLoadError('Unknown version: {!r}'.format(data.get('version')), filename=filename)

        # Output of command is saved outside self._data between execution and save
        self._output = None

        # The check verdict for this job
        self.check_status = None
        self.check_reason = None

        self._data = data

    def __repr__(self):
        return '<{} instance at {:#x}: {}>'.format(
            self.__class__.__name__,
            id(self),
            str(self),
        )

    def __str__(self):
        if not self.is_running:
            return '{!r} not_running'.format(self.name)
        start = time.strftime('%Y-%m-%d %X', time.localtime(self.start_time))
        status = ''
        if self.check_status:
            status = ', status={}'.format(self.check_status)
        return '{name} start={start} ({age} ago), duration={duration}, exit={exit}{status}'.format(
            name = self.name,
            start = start,
            age = self.age,
            duration = self.duration_str,
            exit = self.exit_status,
            status = status,
        )

    @property
    def age(self):
        """ Return how long ago this job executed. """
        if self.start_time is None:
            return 'N/A'
        return _time_to_str(time.time() - self.start_time)

    def status_summary(self):
        """
        Return short string with status of job.

        E.g. 'name[exit=0,age=19h]'
        """
        if not self.is_running:
            return '{name}[not_running]'.format(name = self.name)
        age = _time_to_str(time.time() - self.start_time)
        return '{name}[exit={exit_status},age={age}]'.format(
            name = self.name,
            exit_status = self.exit_status,
            age = age,
            )

    @property
    def name(self):
        """
        The name of the job.

        @rtype: string
        """
        if self._data.get('name') is None:
            return self.cmd
        return self._data['name']

    @property
    def cmd(self):
        """
        The wrapped scripts name.

        @rtype: string
        """
        return self._data['cmd'][0]

    @property
    def args(self):
        """
        The wrapped scripts arguments.

        @rtype: [string]
        """
        return self._data['cmd'][1:]

    @property
    def start_time(self):
        """
        The start time of the script invocation.

        @rtype: int() or None
        """
        if 'start_time' not in self._data:
            return None
        return float(self._data['start_time'])

    @property
    def end_time(self):
        """
        The end time of the script invocation.

        @rtype: int() or None
        """
        if 'end_time' not in self._data:
            return None
        return float(self._data['end_time'])

    @property
    def duration_str(self):
        """
        Time spent executing job, as a human readable string.

        @rtype: string
        """
        if self.end_time is None or self.start_time is None:
            return 'NaN'
        duration = self.end_time - self.start_time
        return _time_to_str(duration)

    @property
    def exit_status(self):
        """
        The exit status of the script invocation.

        @rtype: int() or None
        """
        return self._data.get('exit_status')

    @property
    def pid(self):
        """
        The process ID of the script invocation.

        @rtype: int() or None
        """
        return self._data['pid']

    @property
    def filename(self):
        """
        The filename this job is stored in.

        @rtype: string or None
        """
        return self._data.get('filename')

    @property
    def output(self):
        """
        The output (STDOUT and STDERR) of the script invocation.

        @rtype: [string]
        """
        if self._output is not None:
            return self._output
        if not self._data.get('output') and self.output_filename:
            f = open(self.output_filename, 'r')
            self._data['output'] = f.read()
            f.close()
        return self._data.get('output')

    @property
    def output_filename(self):
        """
        The name of the file holding the output (STDOUT and STDERR) of the script invocation.

        @rtype: string | None
        """
        return self._data.get('output_filename')

    def run(self):
        """
        Run script, storing various aspects of the results.
        """
        self._data['start_time'] = time.time()
        proc = subprocess.Popen(self._data['cmd'],
                                cwd='/',
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                close_fds=True,
                                )
        (stdout, _stderr) = proc.communicate()
        self._data['end_time'] = time.time()
        self._data['exit_status'] = proc.returncode
        self._data['pid'] = proc.pid
        self._output = stdout

    def save_to_file(self, datadir, logger, filename=None):
        """
        Create a record with the details of a script invocation.

        @param datadir: Directory to keep records in
        @param logger: logging logger
        @param filename: Filename to use - default is reasonably constructed

        @type datadir: string
        @type logger: logging.logger
        @type filename: string or None
        """
        if filename is None:
            fn = ''
            for x in self.name:
                if x.isalnum():
                    fn += x
                else:
                    fn += '_'
            filename = '{!s}_{!s}_{!s}'.format(fn, self.start_time, self.pid)
        fn = os.path.join(datadir, filename)
        logger.debug("Saving job metadata to file {!r}.tmp".format(fn))
        output_fn = fn + '_output'
        f = open(fn + '.tmp', 'w')
        if self._output is not None:
            self._data['output_filename'] = output_fn + '.data'
            self._data['output_size'] = len(self._output)
        f.write(json.dumps(self._data, indent = 4, sort_keys = True))
        f.write('\n')
        f.close()
        os.rename(fn + '.tmp', fn + '.json')
        self._data['filename'] = fn

        if self._output is not None:
            output_fn = self.output_filename
            logger.debug("Saving job output to file {!r}".format(output_fn))
            with open(output_fn + '.tmp', 'w') as fd:
                fd.write(self._output)
            os.rename(output_fn + '.tmp', output_fn)
            self._output = None

    def check(self, check, logger):
        """
        Figure out status of this job, based on it's check criterias.

        :type check: Check
        :return: None
        """
        status, msg = check.job_is_ok(self)
        logger.debug('OK check result: {} {}'.format(status, msg))
        if status is True:
            self.check_status = 'OK'
            self.check_reason = ', '.join(msg)
        else:
            status,warn_msg = check.job_is_warning(self)
            logger.debug('Warning check result: {} {}'.format(status, warn_msg))
            msg += warn_msg
            if status is True:
                self.check_status = 'WARNING'
                self.check_reason = ', '.join(msg)
            else:
                self.check_status = 'CRITICAL'
                self.check_reason = ', '.join(msg)

    def is_ok(self):
        return (self.check_status == 'OK')

    def is_warning(self):
        return (self.check_status == 'WARNING')

    @property
    def is_running(self):
        """
        Check if job has executed or not.
        :rtype: bool
        """
        return self.start_time is not None and self.end_time is not None

    @classmethod
    def from_file(cls, filename):
        """
        Initialize this Job instance with data loaded from a file (previously created with
        `save_to_file()'.

        @param filename: Filename to load data from
        @type filename: string

        @rtype: Job
        """
        f = open(filename, 'r')
        try:
            data = json.loads(f.read(100 * 1024 * 1024))
        except ValueError:
            raise JobLoadError('JSON parsing failed', filename=filename)
        f.close()
        data['filename'] = filename
        return cls('', data=data)


class JobsList(object):
    """
    Load all jobs matching any specified name on the command line.

    @param args: Parsed command line arguments
    @param logger: logging logger
    """
    def __init__(self, args, logger, jobs=None, load_not_running=True):
        self.jobs = []
        self._by_name = None
        self._last_of_each = None
        self._args = args
        self._logger = logger

        if jobs is None:
            jobs = []
            files = [f for f in os.listdir(args.datadir) if os.path.isfile(os.path.join(args.datadir, f))]
            for this in files:
                if not this.endswith('.json'):
                    continue
                filename = os.path.join(args.datadir, this)
                try:
                    job = Job.from_file(filename)
                except JobLoadError as exc:
                    logger.warning('Failed loading job file {!r} ({!s})'.format(exc.filename, exc.reason))
                if args.cmd and args.cmd != ['ALL']:
                    if job.name not in args.cmd:
                        logger.debug('Skipping {!r} not matching {!r} (file {!s})'.format(job.name, args.cmd, filename))
                        continue
                jobs.append(job)
        # Sort jobs, oldest first
        self.jobs = sorted(jobs, key = lambda x: x.start_time)

        if load_not_running:
            self._load_not_running()

    def _load_not_running(self):
        """
        Look for jobs that have not executed at all.

        To figure out which jobs _should_ be executed, we make an inventory of all the check files in
        args.checkdir. For some jobs, not_running is an OK/WARNING status, so call the check.not_running()
        to figure that out.
        """
        files = [f for f in os.listdir(self._args.checkdir) if os.path.isfile(os.path.join(self._args.checkdir, f))]
        for this in files:
            if not this.endswith('.ini'):
                continue
            name = this[:-4]  # remove the '.ini' suffix
            if self._args.cmd and self._args.cmd != ['ALL']:
                if name not in self._args.cmd:
                    self._logger.debug('Skipping not-running {!r} not matching {!r} (file {!s})'.format(
                        name, self._args.cmd, this))
                    continue
            if name not in self.by_name:
                filename = os.path.join(self._args.checkdir, this)
                self._logger.debug('Check {!r} (filename {!r}) not found in jobs'.format(name, filename))
                job = Job(name)
                self.jobs.append(job)
                self._by_name[name] = [job]

    @property
    def by_name(self):
        """
        Group jobs by name into a dict - in chronological order.
        :return:
        """
        if self._by_name is None:
            jobs_by_name = {}
            for job in self.jobs:
                if job.name not in jobs_by_name:
                    jobs_by_name[job.name] = []
                jobs_by_name[job.name].append(job)
            self._by_name = jobs_by_name
        return self._by_name

    @property
    def last_of_each(self):
        """
        Get a list of just the last job of each
        :rtype: [Job]
        """
        if self._last_of_each is None:
            _uniq = {}
            for this in self.jobs:
                _uniq[this.name] = this
            self._last_of_each = sorted(_uniq.values(), key=lambda x: x.start_time)
        return self._last_of_each


class Check(object):
    """
    Conditions for the 'check' command. Loaded from file (one file per job name),
    and used to check if a Job instance is OK or WARNING or ...
    """

    def __init__(self, ok_str, warning_str, filename, logger):
        """
        Check criterias typically loaded from a file (using Check.from_file).

        See top-level comment in this script for syntax.

        @param logger: logging logger

        @type logger: logging.logger
        """
        self._logger = logger
        self.filename = filename
        try:
            self._ok_criteria = self._parse_criterias(ok_str)
            self._warning_criteria = self._parse_criterias(warning_str)
        except CheckLoadError as exc:
            raise
        except Exception as exc:
            logger.exception('Failed parsing criterias')
            raise CheckLoadError('Failed loading file', filename)

    def _parse_criterias(self, data_str):
        """
        Parse a full set of criterias, such as 'exit_status=0, max_age=25h'

        :param data_str: Criterias
        :return: [(what, value, negate)]
        """
        res = []
        self._logger.debug('Parsing criterias: {!r}'.format(data_str))
        for this in data_str.split(','):
            this = this.strip()
            if not this:
                continue
            #
            # Backwards-compat for renamed criterias
            #
            replace = {'not_running': '!OR_running',
                       'output_not_contains': '!output_contains',
                       }
            for old, new in replace.items():
                if this == old or this.startswith(old + '='):
                    self._logger.warning('Criteria {!r} in file {} is obsoleted by {!r}'.format(
                        old, self.filename, new))
                    this = new + this[len(old):]

            negate = False
            if this.startswith('!'):
                negate = True
                this = this[1:]
            if '=' not in this:
                # check for allowed single-value criteria
                if this not in ['OR_running']:
                    self._logger.debug('Unrecognized token: {!r}'.format(this))
                    raise CheckLoadError('Bad criteria: {!r}'.format(this), self.filename)
                res += [(this, None, negate)]
                continue
            # parse regular what=value criteria
            (what, value) = this.split('=')
            what = what.strip()
            value = value.strip()
            res += [(what, value, negate)]
        return res

    def job_is_ok(self, job):
        """
        Evaluate a Job against the OK criterias for this check.

        @type job: Job

        @rtype: bool, list
        """
        return self._evaluate(self._ok_criteria, job)

    def job_is_warning(self, job):
        """
        Evaluate a Job against the WARNING criterias for this check.

        @type job: Job

        @rtype: bool, list
        """
        return self._evaluate(self._warning_criteria, job)

    def _evaluate(self, criterias, job):
        """
        The actual evaluation engine.

        For each criteria `foo', look for a corresponding check_foo function and call it.

        @param criterias: List of criterias to test ([('max_age', '8h', False)] for example)
        @param job: The job

        @type criterias: [(string, string | None, bool)]
        @type job: Job

        @returns: True or False, and a list of strings describing success/failure
        @rtype: True | string_types
        """
        ok_msgs = []
        fail_msgs = []

        def separate_or(criterias):
            """ Separate OR_ criterias from the other """
            _or = []
            _and = []
            for this in criterias:
                what, value, negate = this
                if what.startswith('OR_'):
                    _or += [this]
                else:
                    _and += [this]
            return _or, _and

        or_criterias, and_criterias = separate_or(criterias)

        # First, evaluate the OR criterias. If any of them return True, we are done with this check.
        for this in or_criterias:
            self._logger.debug('Evaluating OR {!r}'.format(this))
            status, msg = self._call_check(this, job)
            if status:
                self._logger.debug('OR criteria {} fullfilled: {}'.format(this, msg))
                return True, [msg]
            else:
                fail_msgs += [msg]
        if not and_criterias:
            return False, fail_msgs

        res = True
        for this in and_criterias:
            self._logger.debug('Evaluating AND {!r}'.format(this))
            status, msg = self._call_check(this, job)
            if not status:
                self._logger.debug("Job {!r} failed AND criteria {!r} with status {!r}".format(job, this, status))
                res = False
                fail_msgs += [msg]
            else:
                ok_msgs += [msg]

        if res:
            return True, ok_msgs
        return False, fail_msgs

    def _call_check(self, criteria, job):
        what, value, negate = criteria
        func = getattr(self, 'check_' + what)
        if not func:
            return False, '{}=unknown_criteria'.format(what)
        status, msg = func(job, value, negate)
        self._logger.debug('Function check_{}({!r}) returned: {} {}'.format(
            what, value, status, msg))
        if msg == '':
            # default message is the criteria as a string
            neg_str = '!' if negate else ''
            msg = '{}{}={}'.format(neg_str, what, value)
        return status, msg

    # Functions named check_ are the actual criterias that can be entered in the INI files.
    # These functions should return True, False and a string describing why they succeeded or failed.
    #
    # Negating isn't done in _call_check because some checks formulate their message differently
    # when they are negated.

    def check_exit_status(self, job, value, negate):
        """ Check if job exit status matches 'value' """
        value = int(value)
        res = (job.exit_status == value)
        if negate:
            res = not res
        if res:
            # short message for happy-case
            return True, 'exit={}'.format(value)
        if negate:
            return False, 'exit={}=={}'.format(job.exit_status, value)
        return False, 'exit={}!={}'.format(job.exit_status, value)

    def check_max_age(self, job, value, negate):
        value = _parse_time_value(value)
        now = int(time.time())
        res = (job.end_time > (now - value))
        if negate:
            res = not res
        if res:
            # short message for happy-case
            return True, 'age={}'.format(job.age)
        if negate:
            return False, 'age={}<={}'.format(job.age, _time_to_str(value))
        return False, 'age={}>{}'.format(job.age, _time_to_str(value))

    def check_output_contains(self, job, value, negate):
        value2 = six.b(value) if six.PY3 else value
        res = (value2 in job.output)
        if negate:
            res = not res  # invert result
        neg_str = '!' if negate else ''
        return res, '{}output_contains={}={}'.format(neg_str, value, res)

    def check_output_matches(self, job, value, negate):
        value2 = six.b(value) if six.PY3 else value
        res = re.match(value2, job.output) is not None
        if negate:
            res = not res  # invert result
        neg_str = '!' if negate else ''
        return res, '{}output_matches={}={}'.format(neg_str, value, res)

    def check_OR_running(self, job, value, negate):
        res = job.is_running
        msg = 'is_running' if res else 'not_running'
        if negate:
            res = not res
        return res, msg

    def check_OR_file_exists(self, job, value, negate):
        res = os.path.isfile(value)
        msg = 'file_exists=' if res else 'file_does_not_exist='
        msg += value
        if negate:
            res = not res
        return res, msg

    @classmethod
    def from_file(cls, filename, logger):
        config = configparser.ConfigParser(_check_defaults)
        if not config.read([filename]):
            raise CheckLoadError('Failed reading file', filename)
        _section = 'check'
        try:
            _ok_criteria = config.get(_section, 'ok')
            _warning_criteria = config.get(_section, 'warning')
        except Exception as exc:
            logger.exception(exc)
            raise CheckLoadError('Failed loading file', filename)
        return cls(_ok_criteria, _warning_criteria, filename, logger)


class CheckStatus(object):
    """
    Aggregated status of job invocations for --mode check.

    Attributes:

      checks_ok: List of checks in OK state ([Job()]).
      checks_warning: List of checks in WARNING state ([Job()]).
      checks_critical: List of checks in CRITICAL state ([Job()]).
    """

    def __init__(self, args, logger, jobs=None):
        """
        @param args: Parsed command line arguments
        @param logger: logging logger
        :type jobs: JobsList or None
        """

        self.checks_ok = []
        self.checks_warning = []
        self.checks_unknown = []
        self.checks_critical = []

        self._checks = {}
        self._args = args
        self._logger = logger
        self._last_num_checked = None

        if jobs is not None:
            self.check_jobs(jobs)

    def check_jobs(self, jobs):
        """
        Run checks on a number of jobs.

        Look for job execution entrys (parsed into Job() instances), group them
        per check name and determine the status. For each group, append status
        to one of the three aggregate status lists of this object (checks_ok,
        checks_warning or checks_critical).

        :type jobs: JobsList
        :return:
        """
        self.checks_ok = []
        self.checks_warning = []
        self.checks_unknown = []
        self.checks_critical = []

        # determine total check status based on all logged invocations of this job
        for (name, these_jobs) in jobs.by_name.items():
            try:
                check = self._get_check(name)
            except CheckLoadError as exc:
                self._logger.error('Failed loading check for {}: {}'.format(name, exc.reason))
                this_job = these_jobs[-1]
                this_job.check_status = 'UNKNOWN'
                this_job.check_reason = 'Failed to load check'
                self.checks_unknown.append(this_job)
                continue

            # Check jobs from the tail end since it is pretty probable one
            # will be OK or WARNING. More efficient than wading through tens or
            # hundreds of jobs to find that the last one is OK.
            these_jobs.reverse()

            last = these_jobs[-1] if len(these_jobs) else None
            for job in these_jobs:
                self._logger.debug("Checking {!r}: {!r}".format(name, job))
                job.check(check, self._logger)
                if job.is_ok():
                    self.checks_ok.append(job)
                    break
                elif job.is_warning():
                    self.checks_warning.append(job)
                    break
                elif job == last:
                    self.checks_critical.append(job)

        self._last_num_checked = len(jobs.by_name)

    def _get_check(self, name):
        """
        Load and cache the evaluation criterias for this job.

        :param name: Name of job
        :return: The check
        :rtype: Check
        """
        if name not in self._checks:
            check_filename = os.path.join(self._args.checkdir, name + '.ini')
            self._logger.debug('Loading check definition from {!r}'.format(check_filename))
            try:
                self._checks[name] = Check.from_file(check_filename, self._logger)
            except ScriptHerderError as exc:
                raise CheckLoadError('Failed loading check', filename = check_filename)

        return self._checks[name]

    @property
    def num_jobs(self):
        """
        Return number of jobs processed. This is number of different jobs running + not running.

        @rtype: int
        """
        return self._last_num_checked

    def aggregate_status(self):
        """
        Return the aggregate status of all jobs checked.

        The level returned is 'OK', 'WARNING', 'CRITICAL' or 'UNKNOWN'.

        :return: Level and message
        :rtype: string_types, string_types
        """
        if self.num_jobs == 1:
            # Single job check requested, output detailed information
            if self.checks_ok:
                return 'OK', self.checks_ok[-1].check_reason
            if self.checks_warning:
                return 'WARNING', self.checks_warning[-1].check_reason
            if self.checks_critical:
                return 'CRITICAL', self.checks_critical[-1].check_reason
            if self.checks_unknown:
                return 'UNKNOWN', self.checks_unknown[-1].check_reason
            return 'FAIL', 'No jobs found for {!r}?'.format(self._args.cmd)

        # When looking at multiple jobs at once, logic gets a bit reversed - if ANY
        # job invocation is CRITICAL/WARNING, the aggregate message given to
        # Nagios will have to be a failure.
        if self.checks_critical:
            return 'CRITICAL', _status_summary(self.num_jobs, self.checks_critical)
        if self.checks_warning:
            return 'WARNING', _status_summary(self.num_jobs, self.checks_warning)
        if self.checks_unknown:
            return 'UNKNOWN', _status_summary(self.num_jobs, self.checks_unknown)
        if self.checks_ok:
            return 'OK', _status_summary(self.num_jobs, self.checks_ok)
        return 'UNKNOWN', 'No jobs found?'


def parse_args(defaults):
    """
    Parse the command line arguments

    @param defaults: Argument defaults

    @type defaults: dict
    """
    parser = argparse.ArgumentParser(description = 'Script herder script',
                                     add_help = True,
                                     formatter_class = argparse.ArgumentDefaultsHelpFormatter,
                                     )

    parser.add_argument('--debug',
                        dest = 'debug',
                        action = 'store_true', default = defaults['debug'],
                        help = 'Enable debug operation',
                        )
    parser.add_argument('--syslog',
                        dest = 'syslog',
                        action = 'store_true', default = defaults['syslog'],
                        help = 'Enable syslog output',
                        )
    parser.add_argument('--mode',
                        dest = 'mode',
                        choices = ['wrap', 'ls', 'check', 'lastlog', 'lastfaillog'], default = defaults['mode'],
                        help = 'What mode to run in',
                        )
    parser.add_argument('-d', '--datadir',
                        dest = 'datadir',
                        default = defaults['datadir'],
                        help = 'Data directory',
                        metavar = 'PATH',
                        )
    parser.add_argument('--checkdir',
                        dest = 'checkdir',
                        default = defaults['checkdir'],
                        help = 'Check definitions directory',
                        metavar = 'PATH',
                        )
    parser.add_argument('-N', '--name',
                        dest = 'name',
                        help = 'Job name',
                        metavar = 'NAME',
                        )

    parser.add_argument('cmd',
                        nargs = '*', default = [],
                        help = 'Script command',
                        metavar = 'CMD',
                        )

    args = parser.parse_args()

    return args


def mode_wrap(args, logger):
    """
    Execute a job and save result state in a file.

    @param args: Parsed command line arguments
    @param logger: logging logger
    """
    job = Job(args.name, cmd=args.cmd)
    logger.debug("Invoking '{!s}'".format(''.join(args.cmd)))
    job.run()
    logger.debug("Finished, exit status {!r}".format(job.exit_status))
    logger.debug("Job output:\n{!s}".format(job.output))
    job.save_to_file(args.datadir, logger)
    return True


def mode_ls(args, logger):
    """
    List all the saved states for jobs.

    @param args: Parsed command line arguments
    @param logger: logging logger
    """
    jobs = JobsList(args, logger)
    last_of_each = jobs.last_of_each
    if not args.cmd:
        # Short-mode, just show the last execution for all jobs
        print('\n=== Showing the last execution of each job, use \'--mode ls ALL\' to see all executions\n')
        chosen_jobs = last_of_each
    else:
        chosen_jobs = jobs.jobs

    checkstatus = CheckStatus(args, logger)
    now = int(time.time())

    for this in chosen_jobs:
        if this in last_of_each:
            # For the last instance of each job, evaluate full check-mode status
            temp_jobs = JobsList(None, logger, jobs=[this], load_not_running=False)
            checkstatus.check_jobs(temp_jobs)
            level, msg, = checkstatus.aggregate_status()
        else:
            level = '-'
            if this.exit_status != 0:
                level = 'Non-zero'
            msg = 'exit={}, age={}'.format(this.exit_status, this.age)
        color1 = ''
        color2 = ''
        reset = ''
        if level not in ['OK', '-'] and sys.stdout.isatty():
            color1 = "\033[;1m"  # bold
            color2 = "\033[;1m"  # bold
            reset = "\033[0;0m"
            if level == 'CRITICAL':
                color1 = "\033[1;31m"  # red
        status = '{color1}{level:<8s} {color2}{msg:<20s}{reset}'.format(
            color1 = color1,
            color2 = color2,
            reset = reset,
            level = level,
            msg = msg,
        )
        start = '***'
        if this.start_time:
            start = time.strftime('%Y-%m-%d %X', time.localtime(this.start_time))
        print('{start:>19s}  {duration:>7}  {status}  name={name:<25}  {filename}'.format(
            start = start,
            duration = this.duration_str,
            status = status,
            name = this.name,
            filename = this.filename,
        ))
    return True


def mode_check(args, logger):
    """
    Evaluate the stored states for either a specific job, or all jobs.

    Return Nagios compatible output (scriptherder --mode check is intended to
                                     run using Nagios NRPE or similar).

    @param args: Parsed command line arguments
    @param logger: logging logger
    """

    try:
        status = CheckStatus(args, logger, JobsList(args, logger))
    except CheckLoadError as exc:
        print("UNKNOWN: Failed loading check from file '{!s}' ({!s})".format(exc.filename, exc.reason))
        return exit_status['UNKNOWN']

    level, msg = status.aggregate_status()
    print('{!s}: {!s}'.format(level, msg))
    return exit_status[level]


def mode_lastlog(args, logger, fail_status=False):
    """
    View script output for the last execution for either a specific
    job, or all jobs.

    @param args: Parsed command line arguments
    @param logger: logging logger
    """
    _jobs = JobsList(args, logger)

    if len(_jobs.by_name) > 0:
        view_jobs = []
        for (name, job) in _jobs.last_of_each.items():
            if job.output_filename and os.path.isfile(job.output_filename):
                if fail_status and job.exit_status != 0:
                    view_jobs.append(job)
                elif not fail_status:
                    view_jobs.append(job)

        if view_jobs:
            for job in view_jobs:
                with open(job.output_filename, 'r') as f:
                    print('=== Script output of {!r}'.format(job))
                    shutil.copyfileobj(f, sys.stdout)
                    print('=== End of script output\n')
        else:
            print('No script output found for {!s} with fail_status={!s}'.format(
                ', '.join(_jobs.by_name.keys()), fail_status))
    else:
        print('No jobs found')


def _status_summary(num_jobs, failed):
    """
    String format routine used in output of checks status.
    """
    plural = ''
    if len(failed) != 1:
        plural = 's'

    summary = ', '.join(sorted([str(x.status_summary()) for x in failed]))
    return '{jobs}/{num_jobs} job{plural} in this state: {summary}'.format(
        jobs = len(failed),
        num_jobs = num_jobs,
        summary = summary,
        plural = plural,
    )


def _parse_time_value(value):
    """
    Parse time period strings such as 1d. A lone number is considered number of seconds.

    Return parsed value as number of seconds.

    @param value: Value to parse
    @type value: string
    @rtype: int
    """
    match = re.match(r'^(\d+)([hmsd]*)$', value)
    if match:
        num = int(match.group(1))
        what = match.group(2)
        if what == 'm':
            return num * 60
        if what == 'h':
            return num * 3600
        if what == 'd':
            return num * 86400
        return num


def _time_to_str(value):
    """
    Format number of seconds to short readable string.

    @type value: float or int

    @rtype: string
    """
    if value < 1:
        # milliseconds
        return '{:0.1f}ms'.format(value * 1000)
    if value < 60:
        return '{!s}s'.format(int(value))
    if value < 3600:
        return '{!s}m'.format(int(value / 60))
    if value < 86400:
        return '{!s}h'.format(int(value / 3600))
    days = int(value / 86400)
    return '{!s}d{!s}h'.format(days, int((value % 86400) / 3600))


def main(myname = 'scriptherder', args = None, logger = None, defaults=_defaults):
    """
    Main entry point for either wrapping a script, or checking the status of it.

    @param myname: String, used for logging
    @param args: Command line arguments
    @param logger: logging logger
    @param defaults: Default command line arguments

    @type myname: string
    @type args: None or [string]
    @type logger: logging.logger
    @type defaults: dict
    """
    if not args:
        args = parse_args(defaults)

    # initialize various components
    if not logger:
        level = logging.INFO
        if args.debug:
            level = logging.DEBUG
        logging.basicConfig(level = level, stream = sys.stderr,
                            format = '%(asctime)s: %(threadName)s %(levelname)s %(message)s')
        logger = logging.getLogger(myname)
    if args.debug:
        logger.setLevel(logging.DEBUG)
    if args.syslog:
        syslog_h = logging.handlers.SysLogHandler()
        formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
        syslog_h.setFormatter(formatter)
        logger.addHandler(syslog_h)

    if args.name and args.mode != 'wrap':
        logger.error('Argument --name only applicable for --mode wrap')
        return False

    if args.mode == 'wrap':
        return mode_wrap(args, logger)
    elif args.mode == 'ls':
        return mode_ls(args, logger)
    elif args.mode == 'check':
        return mode_check(args, logger)
    elif args.mode == 'lastlog':
        return mode_lastlog(args, logger)
    elif args.mode == 'lastfaillog':
        return mode_lastlog(args, logger, fail_status=True)
    else:
        logger.error("Invalid mode {!r}".format(args.mode))
        return False


if __name__ == '__main__':
    try:
        progname = os.path.basename(sys.argv[0])
        res = main(progname)
        if isinstance(res, int):
            sys.exit(res)
        if res:
            sys.exit(0)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
