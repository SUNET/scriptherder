#!/usr/bin/env python3
#
# Copyright 2014, 2015, 2017, 2018 SUNET. All rights reserved.
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

Scriptherder can be run in one of the following modes:

   wrap        -- Stores output, exit status etc. about a script invocation
   ls          -- Lists the logged script invocations
   check       -- Check if script execution results match given criteria,
                  output Nagios compatible result
   lastlog     -- Show last execution output of a job (or all jobs)
   lastfaillog -- Show last failed execution output of a job (or all jobs)

The 'check' mode compares job status against criteria in INI-files (in checkdir, default
/etc/scriptherder/check) and produces Nagios compatible output.


Example check file contents for job that is OK if it exited 0 and was last run less
than eight hours ago, WARNING if less than 24 and after that CRITICAL:

    [check]
    ok = exit_status=0, max_age=8h
    warning = exit_status=0, max_age=24h

 All criteria:

    exit_status=0                Must exit(0)
    max_age=8h                   Must have executed less than 8h ago
    not_running                  Job is not running
    output_contains=OK           Output contains the text OK
    output_matches=.*OK.*        Output matches the regexp
    OR_file_exists=FILE          Check if a file exists, such as a disable-file for a job
    OR_running                   True if a job is running - useful for jobs that run @reboot etc.
"""

import argparse
import json
import logging
import logging.handlers
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from typing import Any, AnyStr, Dict, List, Mapping, NewType, Optional, Tuple, Union, cast
from configparser import ConfigParser

Arguments = NewType("Arguments", argparse.Namespace)

# Default arguments
_defaults = {
    "debug": False,
    "syslog": False,
    "mode": "ls",
    "datadir": "/var/cache/scriptherder",
    "checkdir": "/etc/scriptherder/check",
}

_check_defaults = {
    "ok": "exit_status=0,max_age=8h",
    "warning": "exit_status=0,max_age=24h",
}

exit_status = {
    "OK": 0,
    "WARNING": 1,
    "CRITICAL": 2,
    "UNKNOWN": 3,
}


class ScriptHerderError(Exception):
    """
    Base exception class for scriptherder.
    """

    def __init__(self, reason: str, filename: str):
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


class Job:
    """
    Representation of an execution of a job.
    """

    def __init__(self, name: str, cmd: Optional[List[str]] = None, data: Optional[Dict[str, Any]] = None):
        if cmd is None:
            cmd = []
        for x in cmd:
            assert isinstance(x, str)
        if data is None:
            data = {
                "version": 2,
                "name": name,
                "cmd": cmd,
            }
        if data.get("name") is None:
            if cmd:
                data["name"] = os.path.basename(cmd[0])

        if data.get("version") not in [1, 2]:
            raise JobLoadError("Unknown version: {!r}".format(data.get("version")), filename=data["filename"])

        # Output of command is saved outside self._data between execution and save
        self._output: Optional[bytes] = None

        self._data = data

    def __repr__(self) -> str:
        return "<{} instance at {:#x}: {}>".format(
            self.__class__.__name__,
            id(self),
            str(self),
        )

    def __str__(self) -> str:
        if not self.is_running:
            return "{!r} not_running".format(self.name)
        start = time.strftime("%Y-%m-%d %X", time.localtime(self.start_time))
        status = ""
        if self.check_status:
            status = ", status={}".format(self.check_status)
        return "{name} start={start} ({age} ago), duration={duration}, exit={exit}{status}".format(
            name=self.name,
            start=start,
            age=self.age,
            duration=self.duration_str,
            exit=self.exit_status,
            status=status,
        )

    @property
    def age(self) -> str:
        """Return how long ago this job executed."""
        if self.start_time is None:
            return "N/A"
        return _time_to_str(time.time() - self.start_time)

    def status_summary(self) -> str:
        """
        Return short string with status of job.

        E.g. 'name[exit=0,age=19h]'
        """
        if not self.is_running:
            return "{name}[not_running]".format(name=self.name)
        assert self.start_time is not None
        age = _time_to_str(time.time() - self.start_time)
        return "{name}[exit={exit_status},age={age}]".format(
            name=self.name,
            exit_status=self.exit_status,
            age=age,
        )

    @property
    def name(self) -> str:
        """
        The name of the job.
        """
        if self._data.get("name") is None:
            return self.cmd
        assert isinstance(self._data["name"], str)
        return self._data["name"]

    @property
    def cmd(self) -> str:
        """
        The wrapped scripts name.
        """
        assert isinstance(self._data["cmd"], list)
        assert isinstance(self._data["cmd"][0], str)
        return self._data["cmd"][0]

    @property
    def args(self) -> List[str]:
        """
        The wrapped scripts arguments.
        """
        cmd: List[str] = self._data.get("cmd", [])
        assert len(cmd)
        for x in cmd:
            assert isinstance(x, str)
        return cmd[1:]

    @property
    def start_time(self) -> Optional[float]:
        """
        The start time of the script invocation.
        """
        if "start_time" not in self._data:
            return None
        return float(self._data["start_time"])

    @property
    def end_time(self) -> Optional[float]:
        """
        The end time of the script invocation.
        """
        if "end_time" not in self._data:
            return None
        return float(self._data["end_time"])

    @property
    def duration_str(self) -> str:
        """
        Time spent executing job, as a human readable string.
        """
        if self.end_time is None or self.start_time is None:
            return "NaN"
        duration = self.end_time - self.start_time
        return _time_to_str(duration)

    @property
    def exit_status(self) -> Optional[int]:
        """
        The exit status of the script invocation.
        """
        return self._data.get("exit_status")

    @property
    def pid(self) -> Optional[int]:
        """
        The process ID of the script invocation.
        """
        pid = self._data.get("pid")
        assert isinstance(pid, int) or pid is None
        return pid

    @property
    def filename(self) -> Optional[str]:
        """
        The filename this job is stored in.
        """
        return self._data.get("filename")

    @property
    def output(self) -> Optional[bytes]:
        """
        The output (STDOUT and STDERR) of the script invocation.
        """
        if self._output is not None:
            return self._output
        if not self._data.get("output") and self.output_filename:
            f = open(self.output_filename, "r")
            self._data["output"] = f.read()
            f.close()
        return self._data.get("output")

    @property
    def output_filename(self) -> Optional[str]:
        """
        The name of the file holding the output (STDOUT and STDERR) of the script invocation.
        """
        return self._data.get("output_filename")

    @property
    def check_status(self) -> Optional[str]:
        """
        The check verdict for this job, if checked ('OK', 'WARNING', ...)
        """
        return self._data.get("check_status", None)

    @check_status.setter
    def check_status(self, value: str) -> None:
        if value not in exit_status:
            raise ValueError("Unknown check_status {!r}".format(value))
        self._data["check_status"] = value

    @property
    def check_reason(self) -> Optional[str]:
        """
        Text reason for check verdict for this job, if checked.
        """
        return self._data.get("check_reason")

    @check_reason.setter
    def check_reason(self, value: str) -> None:
        self._data["check_reason"] = value

    def run(self) -> None:
        """
        Run script, storing various aspects of the results.
        """
        self._data["start_time"] = time.time()
        proc = subprocess.Popen(
            self._data["cmd"],
            cwd="/",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            close_fds=True,
        )
        (stdout, _stderr) = proc.communicate()
        self._data["end_time"] = time.time()
        self._data["exit_status"] = proc.returncode
        self._data["pid"] = proc.pid
        self._output = stdout
        return None

    def save_to_file(self, datadir: str, logger: logging.Logger, filename: Optional[str] = None) -> None:
        """
        Create a record with the details of a script invocation.

        @param datadir: Directory to keep records in
        @param logger: logging logger
        @param filename: Filename to use - default is reasonably constructed
        """
        if filename is None:
            fn = ""
            for x in self.name:
                if x.isalnum():
                    fn += x
                else:
                    fn += "_"
            assert self.start_time is not None
            _ts = datetime.fromtimestamp(self.start_time)
            _time_str = "{!s}.{:03}".format(
                datetime.fromtimestamp(self.start_time).strftime("%Y%m%dT%H%M%S"), _ts.microsecond
            )
            filename = "{}__ts-{}_pid-{}".format(fn, _time_str, self.pid)
        fn = str(os.path.join(datadir, filename))
        logger.debug("Saving job metadata to file {!r}.tmp".format(fn))
        output_fn = fn + "_output"
        f = open(fn + ".tmp", "w")
        if self._output is not None:
            self._data["output_filename"] = output_fn + ".data"
            self._data["output_size"] = len(self._output)
        f.write(json.dumps(self._data, indent=4, sort_keys=True))
        f.write("\n")
        f.close()
        os.rename(fn + ".tmp", fn + ".json")
        self._data["filename"] = fn

        if self._output is not None:
            assert self.output_filename is not None
            output_fn = self.output_filename
            logger.debug("Saving job output to file {!r}".format(output_fn))
            with open(output_fn + ".tmp", "wb") as fd:
                fd.write(self._output)
            os.rename(output_fn + ".tmp", output_fn)
            self._output = None

    def check(self, check: "Check", logger: logging.Logger) -> None:
        """
        Figure out status of this job, based on it's check criteria.

        :type check: Check
        :type logger: logging.logger
        :return: None
        """
        status, msg = check.job_is_ok(self)
        logger.debug("OK check result: {} {}".format(status, msg))
        if status is True:
            self.check_status = "OK"
            self.check_reason = ", ".join(msg)
        else:
            status, warn_msg = check.job_is_warning(self)
            logger.debug("Warning check result: {} {}".format(status, warn_msg))
            msg += [x for x in warn_msg if x not in msg]
            self.check_status = "WARNING" if status is True else "CRITICAL"
            self.check_reason = ", ".join(msg)
        logger.debug("Stored check status {}, {}".format(self.check_status, self.check_reason))

    def is_ok(self) -> bool:
        return self.check_status == "OK"

    def is_warning(self) -> bool:
        return self.check_status == "WARNING"

    @property
    def is_running(self) -> bool:
        """
        Check if job has executed or not.
        """
        return self.start_time is not None and self.end_time is not None

    @classmethod
    def from_file(cls, filename: str) -> "Job":
        """
        Initialize this Job instance with data loaded from a file (previously created with
        `save_to_file()'.

        @param filename: Filename to load data from
        """
        with open(filename, "rt") as f:
            try:
                data = json.loads(f.read(100 * 1024 * 1024))
            except ValueError:
                raise JobLoadError("JSON parsing failed", filename=filename)
            except Exception as exc:
                raise JobLoadError("Error ({}) loading job output".format(repr(exc)), filename=filename)
        data["filename"] = filename
        return cls("", data=data)


class JobsList:
    """
    Load all jobs matching any specified name on the command line.

    @param args: Parsed command line arguments
    @param logger: logging logger
    @param jobs: List of jobs
    """

    def __init__(
        self, args: Arguments, logger: logging.Logger, jobs: Optional[List[Job]] = None, load_not_running: bool = True
    ):
        self.jobs: List[Job] = []
        self._by_name: Dict[str, List[Job]] = {}
        self._args = args
        self._logger = logger

        if jobs is None:
            jobs = []
            files = [f for f in os.listdir(args.datadir) if os.path.isfile(os.path.join(args.datadir, f))]
            for this in files:
                if not this.endswith(".json"):
                    continue
                filename = os.path.join(args.datadir, this)
                try:
                    job = Job.from_file(filename)
                except JobLoadError as exc:
                    logger.warning("Failed loading job file {!r} ({!s})".format(exc.filename, exc.reason))
                    continue
                if args.names and args.names != ["ALL"]:
                    if job.name not in args.names:
                        logger.debug(
                            "Skipping {!r} not matching {!r} (file {!s})".format(job.name, args.names, filename)
                        )
                        continue
                jobs.append(job)
        # Sort jobs, oldest first
        self.jobs = sorted(jobs, key=lambda x: x.start_time if x.start_time is not None else 0)

        if load_not_running:
            self._load_not_running()

    def _load_not_running(self) -> None:
        """
        Look for jobs that have not executed at all.

        To figure out which jobs _should_ be executed, we make an inventory of all the check files in
        args.checkdir. For some jobs, not_running is an OK/WARNING status, so call the check.not_running()
        to figure that out.
        """
        files = [f for f in os.listdir(self._args.checkdir) if os.path.isfile(os.path.join(self._args.checkdir, f))]
        for this in files:
            if not this.endswith(".ini"):
                continue
            name = this[:-4]  # remove the '.ini' suffix
            if self._args.names and self._args.names != ["ALL"]:
                if name not in self._args.names:
                    self._logger.debug(
                        "Skipping not-running {!r} not matching {!r} (file {!s})".format(name, self._args.names, this)
                    )
                    continue
            if name not in self.by_name:
                filename = os.path.join(self._args.checkdir, this)
                self._logger.debug("Check {!r} (filename {!r}) not found in jobs".format(name, filename))
                job = Job(name)
                self.jobs.append(job)
                if job not in self.by_name.get(name, []):
                    assert self._by_name is not None
                    self._by_name[name] = [job]

    @property
    def by_name(self) -> Dict[str, List[Job]]:
        """
        Group jobs by name into a dict - in chronological order.
        """
        if not self._by_name:
            jobs_by_name: Dict[str, List[Job]] = {}
            for job in self.jobs:
                # Jobs in self.jobs are sorted by start_time, oldest first
                if job.name not in jobs_by_name:
                    jobs_by_name[job.name] = []
                jobs_by_name[job.name].append(job)
            self._by_name = jobs_by_name
        return self._by_name

    @property
    def last_of_each(self) -> List[Job]:
        """
        Get a list of just the last job of each
        """
        res: List[Job] = []
        for jobs in self.by_name.values():
            res.append(jobs[-1])
        self._logger.debug("Last of each: {}".format(res))
        return res


TCriteria = NewType("TCriteria", Tuple[str, Optional[str], bool])


class Check:
    """
    Conditions for the 'check' command. Loaded from file (one file per job name),
    and used to check if a Job instance is OK or WARNING or ...
    """

    def __init__(self, ok_str: str, warning_str: str, filename: str, logger: logging.Logger, runtime_mode: bool):
        """
        Check criteria typically loaded from a file (using Check.from_file).

        See top-level comment in this script for syntax.
        """
        self._logger = logger
        self.filename = filename
        try:
            self._ok_criteria = self._parse_criteria(ok_str, runtime_mode)
            self._warning_criteria = self._parse_criteria(warning_str, runtime_mode)
        except CheckLoadError:
            raise
        except Exception:
            logger.exception("Failed parsing criteria")
            raise CheckLoadError("Failed loading file", filename)
        if not runtime_mode:
            self._ok_criteria += [cast(TCriteria, ("stored_status", "OK", False))]

    def _parse_criteria(self, data_str: str, runtime_mode: bool) -> List[TCriteria]:
        """
        Parse a full set of criteria, such as 'exit_status=0, max_age=25h'

        :param data_str: Criteria
        :return: [(what, value, negate)]
        """
        res: List[TCriteria] = []
        self._logger.debug("Parsing criteria: {!r}".format(data_str))
        for this in data_str.split(","):
            this = this.strip()
            if not this:
                continue
            #
            # Backwards-compat for renamed criteria
            #
            replace = {
                "not_running": "!OR_running",
                "output_not_contains": "!output_contains",
            }
            for old, new in replace.items():
                if this == old or this.startswith(old + "="):
                    self._logger.warning(
                        "Criteria {!r} in file {} is obsoleted by {!r}".format(old, self.filename, new)
                    )
                    this = new + this[len(old) :]

            negate = False
            if this.startswith("!"):
                negate = True
                this = this[1:]
            if "=" not in this:
                # check for allowed single-value criteria
                if this not in ["OR_running"]:
                    self._logger.debug("Unrecognized token: {!r}".format(this))
                    raise CheckLoadError("Bad criteria: {!r}".format(this), self.filename)
                res += [cast(TCriteria, (this, None, negate))]
                continue
            # parse regular what=value criteria
            (what, value) = this.split("=")
            what = what.strip()
            value = value.strip()
            is_runtime_check = what not in ["max_age", "OR_file_exists"]
            if runtime_mode != is_runtime_check:
                self._logger.debug("Skipping criteria {} for runtime_mode={}".format(this, runtime_mode))
                continue
            res += [cast(TCriteria, (what, value, negate))]
        return res

    def job_is_ok(self, job: Job) -> Tuple[bool, List[str]]:
        """
        Evaluate a Job against the OK criteria for this check.

        """
        return self._evaluate("OK", self._ok_criteria, job)

    def job_is_warning(self, job: Job) -> Tuple[bool, List[str]]:
        """
        Evaluate a Job against the WARNING criteria for this check.
        """
        return self._evaluate("warning", self._warning_criteria, job)

    def _evaluate(self, name: str, criteria: List[TCriteria], job: Job) -> Tuple[bool, List[str]]:
        """
        The actual evaluation engine.

        For each criteria `foo', look for a corresponding check_foo function and call it.

        @param name: Name of criteria, used for logging only
        @param criteria: List of criteria to test ([('max_age', '8h', False)] for example)
        @param job: The job

        @returns: True or False, and a list of strings describing success/failure
        """
        ok_msgs: List[str] = []
        fail_msgs: List[str] = []

        def separate_or(criteria: List[TCriteria]) -> Tuple[List[TCriteria], List[TCriteria]]:
            """Separate OR_ criteria from the other"""
            _or: List[TCriteria] = []
            _and: List[TCriteria] = []
            for this in criteria:
                what, _value, _negate = this
                if what.startswith("OR_"):
                    _or += [this]
                else:
                    _and += [this]
            return _or, _and

        or_criteria, and_criteria = separate_or(criteria)

        # First, evaluate the OR criteria. If any of them return True, we are done with this check.
        for this in or_criteria:
            self._logger.debug("Evaluating {!r} condition OR {!s}".format(name, _criteria_to_str(this)))
            status, msg = self._call_check(this, job)
            if status:
                self._logger.debug("{!r} OR criteria {} fulfilled: {}".format(name, this, msg))
                return True, [msg]
            else:
                fail_msgs += [msg]
        if not and_criteria:
            return False, fail_msgs

        res = True
        for this in and_criteria:
            self._logger.debug("Evaluating {!r} condition AND {!s}".format(name, _criteria_to_str(this)))
            status, msg = self._call_check(this, job)
            if not status:
                self._logger.debug(
                    "Job {!r} failed {!r} AND criteria {!r} with status {!r}".format(job, name, this, status)
                )
                res = False
                fail_msgs += [msg]
            else:
                ok_msgs += [msg]

        self._logger.debug("Check {!r} result: {!r}, messages: {!r} / {!r}".format(name, res, ok_msgs, fail_msgs))
        if res:
            return True, ok_msgs
        return False, fail_msgs

    def _call_check(self, criteria: TCriteria, job: Job) -> Tuple[bool, str]:
        what, value, negate = criteria
        func = getattr(self, "check_" + what)
        if not func:
            return False, "{}=unknown_criteria".format(what)
        status, msg = func(job, value, negate)
        self._logger.debug("Function check_{}({!r}) returned: {} {}".format(what, value, status, msg))
        if msg == "":
            # default message is the criteria as a string
            neg_str = "!" if negate else ""
            msg = "{}{}={}".format(neg_str, what, value)
        return status, msg

    # Functions named check_ are the actual criteria that can be entered in the INI files.
    # These functions should return True, False and a string describing why they succeeded or failed.
    #
    # Negating isn't done in _call_check because some checks formulate their message differently
    # when they are negated.

    def check_exit_status(self, job: Job, value: str, negate: bool) -> Tuple[bool, str]:
        """Check if job exit status matches 'value'"""
        res = job.exit_status == int(value)
        if negate:
            res = not res
        if res:
            # short message for happy-case
            return True, "exit={}".format(value)
        if negate:
            return False, "exit={}=={}".format(job.exit_status, value)
        return False, "exit={}!={}".format(job.exit_status, value)

    def check_max_age(self, job: Job, value: str, negate: bool) -> Tuple[bool, str]:
        _value = _parse_time_value(value)
        assert _value is not None
        now = int(time.time())
        if job.end_time is None:
            res = False
        else:
            res = job.end_time > (now - _value)
        if negate:
            res = not res
        if res:
            # No message for happy-case
            return True, ""
        if negate:
            return False, "age={}<={}".format(job.age, _time_to_str(_value))
        return False, "age={}>{}".format(job.age, _time_to_str(_value))

    def check_output_contains(self, job: Job, value: str, negate: bool) -> Tuple[bool, str]:
        _output_bytes = b"" if job.output is None else _to_bytes(job.output)
        res = _to_bytes(value) in _output_bytes
        if negate:
            res = not res  # invert result
        neg_str = "!" if negate else ""
        return res, "{}output_contains={}=={}".format(neg_str, value, res)

    def check_output_matches(self, job: Job, value: str, negate: bool) -> Tuple[bool, str]:
        res = re.match(_to_bytes(value), _to_bytes(job.output)) is not None
        if negate:
            res = not res  # invert result
        neg_str = "!" if negate else ""
        return res, "{}output_matches={}=={}".format(neg_str, value, res)

    def check_OR_running(self, job: Job, value: str, negate: bool) -> Tuple[bool, str]:
        res = job.is_running
        msg = "is_running" if res else "not_running"
        if negate:
            res = not res
        return res, msg

    def check_OR_file_exists(self, job: Job, value: str, negate: bool) -> Tuple[bool, str]:
        res = os.path.isfile(value)
        msg = "file_exists=" if res else "file_does_not_exist="
        msg += value
        if negate:
            res = not res
        return res, msg

    def check_stored_status(self, job: Job, value: str, negate: bool) -> Tuple[bool, str]:
        res = job.check_status == value
        if negate:
            res = not res  # invert result
        neg_str = "!" if negate else ""
        return res, "{}stored_status={}=={}".format(neg_str, value, res)

    @classmethod
    def from_file(cls, filename: str, logger: logging.Logger, runtime_mode: bool = False) -> "Check":
        config = ConfigParser(_check_defaults)
        if not config.read([filename]):
            raise CheckLoadError("Failed reading file", filename)
        _section = "check"
        try:
            _ok_criteria = config.get(_section, "ok")
            _warning_criteria = config.get(_section, "warning")
        except Exception as exc:
            logger.exception(exc)
            raise CheckLoadError("Failed loading file", filename)
        return cls(_ok_criteria, _warning_criteria, filename, logger, runtime_mode)


class CheckStatus:
    """
    Aggregated status of job invocations for --mode check.

    Attributes:

      checks_ok: List of checks in OK state ([Job()]).
      checks_warning: List of checks in WARNING state ([Job()]).
      checks_critical: List of checks in CRITICAL state ([Job()]).
    """

    def __init__(
        self,
        args: Arguments,
        logger: logging.Logger,
        runtime_mode: bool = False,
        jobs: Optional[JobsList] = None,
        checks: Optional[Dict[str, Check]] = None,
    ):
        """
        @param args: Parsed command line arguments
        @param logger: logging logger
        @param runtime_mode: Execute runtime-checks (not age) or the other way around
        """

        self.checks_ok: List[Job] = []
        self.checks_warning: List[Job] = []
        self.checks_unknown: List[Job] = []
        self.checks_critical: List[Job] = []

        self._checks: Dict[str, Check] = {} if checks is None else checks
        self._args = args
        self._logger = logger
        self._runtime_mode = runtime_mode
        self._last_num_checked = 0

        if jobs is not None:
            self.check_jobs(jobs)

    def check_jobs(self, jobs: JobsList) -> None:
        """
        Run checks on a number of jobs.

        Look for job execution entries (parsed into Job() instances), group them
        per check name and determine the status. For each group, append status
        to one of the three aggregate status lists of this object (checks_ok,
        checks_warning or checks_critical).
        """

        self.checks_ok = []
        self.checks_warning = []
        self.checks_unknown = []
        self.checks_critical = []

        # determine total check status based on all logged invocations of this job
        for (name, these_jobs) in jobs.by_name.items():
            self._logger.debug("")
            try:
                check = self.get_check(name)
            except CheckLoadError as exc:
                self._logger.error("Failed loading check for {}: {}".format(name, exc.reason))
                this_job = these_jobs[-1]
                this_job.check_status = "UNKNOWN"
                this_job.check_reason = "Failed to load check"
                self.checks_unknown.append(this_job)
                continue

            # Check most recent job first since it is pretty probable one
            # will be OK or WARNING. More efficient than wading through tens or
            # hundreds of jobs to find that the last one is OK.
            these_jobs.reverse()

            matched = False
            for job in these_jobs:
                self._logger.debug("Checking {!r}: {!r}".format(name, job))
                job.check(check, self._logger)
                self._logger.debug("Checking for OK status")
                if job.is_ok():
                    self._logger.debug("Job status is OK")
                    self.checks_ok.append(job)
                    matched = True
                    break
                else:
                    self._logger.debug("Checking for WARNING status")
                    if job.is_warning():
                        self._logger.debug("Job status is WARNING")
                        self.checks_warning.append(job)
                        matched = True
                        break

            if not matched:
                self._logger.debug("Concluding CRITICAL status")
                self.checks_critical.append(these_jobs[0])

        self._last_num_checked = len(jobs.by_name)

    def get_check(self, name: str) -> Check:
        """
        Load and cache the evaluation criteria for this job.

        :param name: Name of job
        :return: The check
        """
        if name not in self._checks:
            check_filename = os.path.join(self._args.checkdir, name + ".ini")
            self._logger.debug("Loading check definition from {!r}".format(check_filename))
            try:
                self._checks[name] = Check.from_file(check_filename, self._logger, runtime_mode=self._runtime_mode)
            except ScriptHerderError:
                raise CheckLoadError("Failed loading check", filename=check_filename)

        return self._checks[name]

    @property
    def num_jobs(self) -> int:
        """
        Return number of jobs processed. This is number of different jobs running + not running.
        """
        return self._last_num_checked

    def aggregate_status(self) -> Tuple[str, Optional[str]]:
        """
        Return the aggregate status of all jobs checked.

        The level returned is 'OK', 'WARNING', 'CRITICAL' or 'UNKNOWN'.

        :return: Level and message
        """
        if self.num_jobs == 1:
            # Single job check requested, output detailed information
            if self.checks_ok:
                return "OK", self.checks_ok[-1].check_reason
            if self.checks_warning:
                return "WARNING", self.checks_warning[-1].check_reason
            if self.checks_critical:
                return "CRITICAL", self.checks_critical[-1].check_reason
            if self.checks_unknown:
                return "UNKNOWN", self.checks_unknown[-1].check_reason
            return "FAIL", "No jobs found for {!r}?".format(self._args.names)

        # When looking at multiple jobs at once, logic gets a bit reversed - if ANY
        # job invocation is CRITICAL/WARNING, the aggregate message given to
        # Nagios will have to be a failure.
        if self.checks_critical:
            return "CRITICAL", _status_summary(self.num_jobs, self.checks_critical)
        if self.checks_warning:
            return "WARNING", _status_summary(self.num_jobs, self.checks_warning)
        if self.checks_unknown:
            return "UNKNOWN", _status_summary(self.num_jobs, self.checks_unknown)
        if self.checks_ok:
            return "OK", _status_summary(self.num_jobs, self.checks_ok)
        return "UNKNOWN", "No jobs found?"


def parse_args(defaults: Mapping[str, Any]) -> Arguments:
    """
    Parse the command line arguments

    @param defaults: Argument defaults
    """
    parser = argparse.ArgumentParser(
        description="Script herder script",
        add_help=True,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "--debug", dest="debug", action="store_true", default=defaults["debug"], help="Enable debug operation"
    )
    parser.add_argument(
        "-d", "--datadir", dest="datadir", default=defaults["datadir"], help="Data directory", metavar="PATH"
    )
    parser.add_argument(
        "--checkdir", dest="checkdir", default=defaults["checkdir"], help="Check definitions directory", metavar="PATH"
    )

    subparsers = parser.add_subparsers(
        help="Mode of operation",
        dest="mode",
    )

    parser_wrap = subparsers.add_parser("wrap", help="Wrap a command and store metadata about it")
    parser_ls = subparsers.add_parser("ls", help="List jobs (jobs are created with 'wrap'")
    parser_check = subparsers.add_parser("check", help="Return status of jobs in a Nagios compatible way")
    parser_lastlog = subparsers.add_parser("lastlog", help="Show last entry for a job")
    parser_lastfaillog = subparsers.add_parser("lastfaillog", help="Show last failure entry for a job")

    parser_wrap.add_argument("-N", "--name", dest="name", help="Job name", metavar="NAME", required=True)
    parser_wrap.add_argument("cmd", nargs="+", default=[], help="Script command", metavar="CMD")
    parser_wrap.add_argument(
        "--syslog", dest="syslog", action="store_true", default=defaults["syslog"], help="Enable syslog output"
    )

    parser_ls.add_argument("names", nargs="*", default=[], help="Names of jobs to include", metavar="NAME")
    parser_check.add_argument("names", nargs="*", default=[], help="Names of jobs to include", metavar="NAME")
    parser_lastlog.add_argument("names", nargs="*", default=[], help="Names of jobs to include", metavar="NAME")
    parser_lastfaillog.add_argument("names", nargs="*", default=[], help="Names of jobs to include", metavar="NAME")

    _args = sys.argv[1:]
    if _args and _args[0] == "--mode":
        # Old style invocation. Need to remove the "--mode" argument to have the subparser execute.
        _args = _args[1:]
    if not _args:
        # If we set subparsers.default to "ls", the parser_ls won't execute and there won't be an args.name
        # which causes issues later on. So we need to add a dummy argument to make the parser execute.
        _args = ["ls"]

    args = parser.parse_args(_args)

    return cast(Arguments, args)


class ColumnMeta:
    """
    Metadata for a column
    """

    def __init__(self, name: str, width: int = 0, align: str = ""):
        self.name = name
        self.width = width
        self.align = align
        self.update_width(len(name))

    def update_width(self, value: int) -> None:
        if value > self.width:
            self.width = value

    def to_string(self, element: Tuple[str, int]) -> str:
        (value, print_width) = element
        _pad = " " * (self.width - print_width)
        if self.align == "right":
            return _pad + value
        return value + _pad


class DataTable:
    """Format data in fixed-width columns"""

    def __init__(self, meta: List[ColumnMeta]) -> None:
        self.rows: List[List[Tuple[str, int]]] = []
        self._curr: List[Tuple[str, int]] = []
        self._meta = meta

        self.without_ANSI = re.compile(
            r"""
            \x1b     # literal ESC
            \[       # literal [
            [;\d]*   # zero or more digits or semicolons
            [A-Za-z] # a letter
            """,
            re.VERBOSE,
        ).sub

    def push(self, value: str) -> None:
        """Add a value to the current row"""
        _print_width = len(self.without_ANSI("", value))  # get the actual print width for this value
        self._curr.append((value, _print_width))

        if len(self._meta) >= len(self._curr):
            _meta = self._meta[len(self._curr) - 1]
            _meta.update_width(len(self.without_ANSI("", value)))

    def new_line(self) -> None:
        self.rows.append(self._curr)
        self._curr = []

    def __str__(self) -> str:
        """Return the formatted table"""
        res: List[str] = []

        # Output field names
        _this = ""
        for header in self._meta:
            _element = (header.name, len(header.name))
            _this += f"{header.to_string(_element)}  "
        _this = _this.rstrip()
        res.append(_this)

        # Output data rows
        for row in self.rows:
            _this = ""
            for idx in range(len(row)):
                if len(self._meta) >= idx:
                    _meta = self._meta[idx]
                    _this += _meta.to_string(row[idx])
                else:
                    _this += str(row[idx])
                _this += "  "
            _this = _this.rstrip()
            res.append(_this)
        return "\n".join(res)


def mode_wrap(args: Arguments, logger: logging.Logger) -> bool:
    """
    Execute a job and save result state in a file.

    @param args: Parsed command line arguments
    @param logger: logging logger
    """
    job = Job(args.name, cmd=args.cmd)
    logger.debug("Invoking '{!s}'".format("".join(args.cmd)))
    job.run()
    logger.debug("Finished, exit status {!r}".format(job.exit_status))
    logger.debug("Job output:\n{!s}".format(job.output))
    # Record what the jobs status evaluates to at the time of execution
    checkstatus = CheckStatus(args, logger, runtime_mode=True)
    try:
        check = checkstatus.get_check(job.name)
    except CheckLoadError:
        check = None
    if check:
        job.check(check, logger)
        level = logging.INFO if job.is_ok() else logging.WARNING
        logger.log(level, "Job {!r} check status is {} ({})".format(job.name, job.check_status, job.check_reason))
    job.save_to_file(args.datadir, logger)
    return True


def mode_ls(args: Arguments, logger: logging.Logger) -> bool:
    """
    List all the saved states for jobs.

    @param args: Parsed command line arguments
    @param logger: logging logger
    """
    jobs = JobsList(args, logger)
    last_of_each = jobs.last_of_each
    if not args.names:
        # Short-mode, just show the last execution for all jobs
        print("\n=== Showing the last execution of each job, use 'ls ALL' to see all executions\n")
        chosen_jobs = last_of_each
    else:
        chosen_jobs = jobs.jobs

    checkstatus = CheckStatus(args, logger)

    _fields = [
        ColumnMeta("Start time", align="right"),
        ColumnMeta("Duration"),
        ColumnMeta("Age"),
        ColumnMeta("Status"),
        ColumnMeta("Criteria"),
        ColumnMeta("Name"),
        ColumnMeta("Filename"),
    ]
    data = DataTable(meta=_fields)

    for this in chosen_jobs:
        start = "***"
        if this.start_time:
            start = time.strftime("%Y-%m-%d %X", time.localtime(this.start_time))
        data.push(start)
        data.push(this.duration_str)
        data.push(this.age + " ago")

        if this in last_of_each:
            # For the last instance of each job, evaluate full check-mode status
            temp_jobs = JobsList(args, logger, jobs=[this], load_not_running=False)
            checkstatus.check_jobs(temp_jobs)
            (level, msg) = checkstatus.aggregate_status()
        else:
            level = "-"
            if this.exit_status != 0:
                level = "Non-zero"
            msg = "exit={}, age={}".format(this.exit_status, this.age)

        color1 = ""
        color2 = ""
        reset = ""
        if level not in ["OK", "-"] and sys.stdout.isatty():
            color1 = "\033[;1m"  # bold
            color2 = "\033[;1m"  # bold
            reset = "\033[0;0m"
            if level == "CRITICAL":
                color1 = "\033[1;31m"  # red

        data.push(color1 + level + reset)
        data.push(color2 + (msg or "") + reset)

        data.push(this.name)
        data.push(this.filename or "")
        data.new_line()

    print(data)
    return True


def mode_check(args: Arguments, logger: logging.Logger) -> int:
    """
    Evaluate the stored states for either a specific job, or all jobs.

    Return Nagios compatible output ("scriptherder check" is intended to
                                     run using Nagios NRPE or similar).

    @param args: Parsed command line arguments
    @param logger: logging logger
    """

    try:
        status = CheckStatus(args, logger, jobs=JobsList(args, logger))
    except CheckLoadError as exc:
        print("UNKNOWN: Failed loading check from file '{!s}' ({!s})".format(exc.filename, exc.reason))
        return exit_status["UNKNOWN"]

    level, msg = status.aggregate_status()
    print("{!s}: {!s}".format(level, msg))
    return exit_status[level]


def mode_lastlog(args: Arguments, logger: logging.Logger, fail_status: bool = False) -> Optional[int]:
    """
    View script output for the last execution for either a specific
    job, or all jobs.

    @param args: Parsed command line arguments
    @param logger: logging logger
    @param fail_status: Show last failed log if True
    """
    _jobs = JobsList(args, logger)

    if not _jobs.jobs:
        print("No jobs found")
        return None

    view_jobs: List[Job] = []
    for job in _jobs.last_of_each:
        if job.output_filename and os.path.isfile(job.output_filename):
            if fail_status and job.exit_status != 0:
                view_jobs.append(job)
            elif not fail_status:
                view_jobs.append(job)

    if view_jobs:
        for job in view_jobs:
            if not job.output_filename:
                continue
            with open(job.output_filename, "r") as f:
                print("=== Script output of {!r}".format(job))
                shutil.copyfileobj(f, sys.stdout)
                print("=== End of script output\n")
    else:
        print(
            "No script output found for {!s} with fail_status={!s}".format(", ".join(_jobs.by_name.keys()), fail_status)
        )

    return bool(view_jobs)


def _status_summary(num_jobs: int, failed: List[Job]) -> str:
    """
    String format routine used in output of checks status.
    """
    plural = "s" if num_jobs != 1 else ""

    summary = ", ".join(sorted([str(x.status_summary()) for x in failed]))
    return "{jobs}/{num_jobs} job{plural} in this state: {summary}".format(
        jobs=len(failed),
        num_jobs=num_jobs,
        summary=summary,
        plural=plural,
    )


def _parse_time_value(value: str) -> Optional[int]:
    """
    Parse time period strings such as 1d. A lone number is considered number of seconds.

    Return parsed value as number of seconds.

    @param value: Value to parse
    """
    match = re.match(r"^(\d+)([hmsd]*)$", value)
    if match:
        num = int(match.group(1))
        what = match.group(2)
        if what == "m":
            return num * 60
        if what == "h":
            return num * 3600
        if what == "d":
            return num * 86400
        return num
    return None


def _time_to_str(value: Union[float, int]) -> str:
    """
    Format number of seconds to short readable string.
    """
    if value < 1:
        # milliseconds
        return "{!s}ms".format(int(value * 1000))
    if value < 60:
        return "{!s}s".format(int(value))
    if value < 3600:
        return "{!s}m".format(int(value / 60))
    if value < 86400:
        return "{!s}h".format(int(value / 3600))
    days = int(value / 86400)
    return "{!s}d{!s}h".format(days, int((value % 86400) / 3600))


def _to_bytes(data: Optional[AnyStr]) -> bytes:
    if not data:
        return b""
    if isinstance(data, bytes):
        return data
    return data.encode("utf-8")


def _criteria_to_str(criteria: TCriteria) -> str:
    name, value, negate = criteria
    eq = "!=" if negate else "=="
    return "{}{}{}".format(name, eq, value)


def main(myname: str, args: Arguments, logger: Optional[logging.Logger] = None) -> Optional[Union[int, bool]]:
    """
    Main entry point for either wrapping a script, or checking the status of it.

    @param myname: String, used for logging
    @param args: Command line arguments
    @param logger: logging logger
    @param defaults: Default command line arguments
    """
    # initialize various components
    if not logger:
        level = logging.INFO
        if args.debug:
            level = logging.DEBUG
        logging.basicConfig(
            level=level, stream=sys.stderr, format="%(asctime)s: %(threadName)s %(levelname)s %(message)s"
        )
        logger = logging.getLogger(myname)
    # If stderr is not a TTY, change the log level of the StreamHandler (stream = sys.stderr above) to ERROR
    if not sys.stderr.isatty() and not args.debug:
        for this_h in logging.getLogger("").handlers:
            this_h.setLevel(logging.ERROR)
    if args.debug:
        logger.setLevel(logging.DEBUG)
    if args.syslog:
        syslog_h = logging.handlers.SysLogHandler("/dev/log")
        formatter = logging.Formatter("%(name)s: %(levelname)s %(message)s")
        syslog_h.setFormatter(formatter)
        syslog_h.setLevel(logging.INFO)
        logger.addHandler(syslog_h)

    if args.mode == "wrap":
        return mode_wrap(args, logger)
    elif args.mode == "ls":
        return mode_ls(args, logger)
    elif args.mode == "check":
        return mode_check(args, logger)
    elif args.mode == "lastlog":
        return mode_lastlog(args, logger)
    elif args.mode == "lastfaillog":
        return mode_lastlog(args, logger, fail_status=True)
    logger.error("Invalid mode {!r}".format(args.mode))
    return False


if __name__ == "__main__":
    try:
        progname = os.path.basename(sys.argv[0])
        args = parse_args(_defaults)
        res = main(progname, args=args)
        if isinstance(res, int):
            sys.exit(res)
        if res:
            sys.exit(0)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
