'''
Verify remap.config acl behavior.
'''
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
# #      http://www.apache.org/licenses/LICENSE-2.0 #
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import os
import io
import re
import inspect
import tempfile
from yaml import load, dump
from yaml import CLoader as Loader
from typing import List, Tuple

Test.Summary = '''
Verify remap.config acl behavior.
'''


class Test_remap_acl:
    """Configure a test to verify remap.config acl behavior."""

    _ts_counter: int = 0
    _server_counter: int = 0
    _client_counter: int = 0

    def __init__(
            self, name: str, replay_file: str, ip_allow_content: str, deactivate_ip_allow: bool, acl_behavior_policy: int,
            acl_configuration: str, named_acls: List[Tuple[str, str]], expected_responses: List[int], proxy_protocol: bool):
        """Initialize the test.

        :param name: The name of the test.
        :param replay_file: The replay file to be used.
        :param ip_allow_content: The ip_allow configuration to be used.
        :param deactivate_ip_allow: Whether to deactivate the ip_allow filter.
        :param acl_configuration: The ACL configuration to be used.
        :param named_acls: The set of named ACLs to configure and use.
        :param expect_responses: The in-order expected responses from the proxy.
        """
        self._replay_file = replay_file
        self._ip_allow_content = ip_allow_content
        self._deactivate_ip_allow = deactivate_ip_allow
        self._acl_behavior_policy = acl_behavior_policy
        self._acl_configuration = acl_configuration
        self._named_acls = named_acls
        self._expected_responses = expected_responses

        tr = Test.AddTestRun(name)
        self._configure_server(tr)
        self._configure_traffic_server(tr, proxy_protocol)
        self._configure_client(tr, proxy_protocol)

    def _configure_server(self, tr: 'TestRun') -> None:
        """Configure the server.

        :param tr: The TestRun object to associate the server process with.
        """
        name = f"server-{Test_remap_acl._server_counter}"
        server = tr.AddVerifierServerProcess(name, self._replay_file)
        Test_remap_acl._server_counter += 1
        self._server = server

    def _configure_traffic_server(self, tr: 'TestRun', proxy_protocol: bool) -> None:
        """Configure Traffic Server.

        :param tr: The TestRun object to associate the Traffic Server process with.
        """

        name = f"ts-{Test_remap_acl._ts_counter}"
        ts = tr.MakeATSProcess(name, enable_cache=False, enable_proxy_protocol=proxy_protocol, enable_uds=False)
        Test_remap_acl._ts_counter += 1
        self._ts = ts

        ts.Disk.records_config.update(
            {
                'proxy.config.diags.debug.enabled': 1,
                'proxy.config.diags.debug.tags': 'http|url|remap|ip_allow|proxyprotocol',
                'proxy.config.http.push_method_enabled': 1,
                'proxy.config.http.connect_ports': self._server.Variables.http_port,
                'proxy.config.url_remap.acl_behavior_policy': self._acl_behavior_policy,
                'proxy.config.acl.subjects': 'PROXY,PEER',
            })

        remap_config_lines = []
        if self._deactivate_ip_allow:
            remap_config_lines.append('.deactivatefilter ip_allow')

        # First, define the name ACLs (filters).
        for name, definition in self._named_acls:
            remap_config_lines.append(f'.definefilter {name} {definition}')
        # Now activate them.
        for name, _ in self._named_acls:
            remap_config_lines.append(f'.activatefilter {name}')

        remap_config_lines.append(f'map / http://127.0.0.1:{self._server.Variables.http_port} {self._acl_configuration}')
        ts.Disk.remap_config.AddLines(remap_config_lines)
        ts.Disk.ip_allow_yaml.AddLines(self._ip_allow_content.split("\n"))

    def _configure_client(self, tr: 'TestRun', proxy_protocol: bool) -> None:
        """Run the test.

        :param tr: The TestRun object to associate the client process with.
        """

        name = f"client-{Test_remap_acl._client_counter}"
        port = self._ts.Variables.port if proxy_protocol == False else self._ts.Variables.proxy_protocol_port
        p = tr.AddVerifierClientProcess(name, self._replay_file, http_ports=[port])
        Test_remap_acl._client_counter += 1
        p.StartBefore(self._server)
        p.StartBefore(self._ts)

        if self._expected_responses == [None, None]:
            # If there are no expected responses, expect the Warning about the rejected ip.
            self._ts.Disk.diags_log.Content += Testers.ContainsExpression(
                "client '127.0.0.1' prohibited by ip-allow policy", "Verify the client rejection warning message.")

            # Also, the client will complain about the broken connections.
            p.ReturnCode = 1

        else:
            codes = [str(code) for code in self._expected_responses]
            p.Streams.stdout += Testers.ContainsExpression(
                '.*'.join(codes), "Verifying the expected order of responses", reflags=re.DOTALL | re.MULTILINE)


class Test_old_action:
    _ts_counter: int = 0

    def __init__(self, name: str, acl_filter: str, ip_allow_content: str) -> None:
        '''Test that ATS fails with a FATAL message if an old action is used with modern ACL filter policy.

        :param name: The name of the test run.
        :param acl_filter: The ACL filter to use.
        :param ip_allow_content: The ip_allow configuration to use.
        '''

        tr = Test.AddTestRun(name)
        ts = self._configure_traffic_server(tr, acl_filter, ip_allow_content)

    def _configure_traffic_server(self, tr: 'TestRun', acl_filter: str, ip_allow_content: str) -> 'Process':
        '''Configure Traffic Server process

        :param tr: The TestRun object to associate the Traffic Server process with.
        :param acl_filter: The ACL filter to configure in remap.config.
        :param ip_allow_content: The ip_allow configuration to use.
        :return: The Traffic Server process.
        '''
        name = f"ts-old-action-{Test_old_action._ts_counter}"
        Test_old_action._ts_counter += 1
        ts = tr.MakeATSProcess(name, enable_uds=False)
        self._ts = ts

        ts.Disk.records_config.update(
            {
                'proxy.config.diags.debug.enabled': 1,
                'proxy.config.diags.debug.tags': 'http|url|remap|ip_allow',
                'proxy.config.url_remap.acl_behavior_policy': 1,
            })

        ts.Disk.remap_config.AddLine(f'map / http://127.0.0.1:8080 {acl_filter}')
        if ip_allow_content:
            ts.Disk.ip_allow_yaml.AddLines(ip_allow_content.split("\n"))

        if acl_filter != '':
            expected_error = '"allow" and "deny" are no longer valid.'
        else:
            expected_error = 'Legacy action name of'

        # We have to wait upon TS to emit the expected log message, but it cannot be
        # the ts Ready criteria because autest might detect the process going away
        # before it detects the log message. So we add a separate process that waits
        # upon the log message.
        watcher = tr.Processes.Process("watcher")
        watcher.Command = "sleep 10"
        watcher.Ready = When.FileContains(ts.Disk.diags_log.Name, expected_error)
        watcher.StartBefore(ts)

        tr.Processes.Default.Command = 'printf "Fatal Shutdown Test"'
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.StartBefore(watcher)

        tr.Timeout = 5
        ts.ReturnCode = Any(33, 70)
        ts.Ready = 0
        ts.Disk.diags_log.Content = Testers.IncludesExpression(expected_error, 'ATS should fatal with the old actions.')

        return ts


IP_ALLOW_OLD_ACTION = f'''
ip_categories:
  - name: ACME_LOCAL
    ip_addrs: 127.0.0.1
  - name: ACME_EXTERNAL
    ip_addrs: 5.6.7.8

ip_allow:
  - apply: in
    ip_addrs: 0/0
    action: allow
    methods:
      - GET
'''

IP_ALLOW_CONTENT = f'''
ip_categories:
  - name: ACME_LOCAL
    ip_addrs: 127.0.0.1
  - name: ACME_EXTERNAL
    ip_addrs: 5.6.7.8

ip_allow:
  - apply: in
    ip_addrs: 0/0
    action: set_allow
    methods:
      - GET
'''

Test_old_action("Verify allow is reject in modern policy", "@action=allow @method=GET", IP_ALLOW_CONTENT)
Test_old_action("Verify deny is reject in modern policy", "@action=deny @method=GET", IP_ALLOW_CONTENT)
Test_old_action("Verify deny is reject in modern policy", "", IP_ALLOW_OLD_ACTION)

test_ip_allow_optional_methods = Test_remap_acl(
    "Verify non-allowed methods are blocked.",
    replay_file='remap_acl_get_post_allowed.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=False,
    acl_behavior_policy=1,
    acl_configuration='@action=set_allow @src_ip=127.0.0.1 @method=GET @method=POST',
    named_acls=[],
    expected_responses=[200, 200, 403, 403, 403],
    proxy_protocol=False)

test_ip_allow_optional_methods_pp = Test_remap_acl(
    "Verify non-allowed methods are blocked (PP).",
    replay_file='remap_acl_get_post_allowed_pp.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=False,
    acl_behavior_policy=1,
    acl_configuration='@action=set_allow @src_ip=1.2.3.4 @method=GET @method=POST',
    named_acls=[],
    expected_responses=[200, 200, 403, 403, 403],
    proxy_protocol=True)

test_ip_allow_optional_methods = Test_remap_acl(
    "Verify add_allow adds an allowed method.",
    replay_file='remap_acl_get_post_allowed.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=False,
    acl_behavior_policy=1,
    acl_configuration='@action=add_allow @src_ip=127.0.0.1 @method=POST',
    named_acls=[],
    expected_responses=[200, 200, 403, 403, 403],
    proxy_protocol=False)

test_ip_allow_optional_methods = Test_remap_acl(
    "Verify add_allow adds allowed methods.",
    replay_file='remap_acl_get_post_allowed.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=False,
    acl_behavior_policy=1,
    acl_configuration='@action=add_allow @src_ip=127.0.0.1 @method=GET @method=POST',
    named_acls=[],
    expected_responses=[200, 200, 403, 403, 403],
    proxy_protocol=False)

test_ip_allow_optional_methods = Test_remap_acl(
    "Verify if no ACLs match, ip_allow.yaml is used.",
    replay_file='remap_acl_get_allowed.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=False,
    acl_behavior_policy=1,
    acl_configuration='@action=set_allow @src_ip=1.2.3.4 @method=GET @method=POST',
    named_acls=[],
    expected_responses=[200, 403, 403, 403, 403],
    proxy_protocol=False)

test_ip_allow_optional_methods = Test_remap_acl(
    "Verify @src_ip=all works.",
    replay_file='remap_acl_get_post_allowed.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=False,
    acl_behavior_policy=1,
    acl_configuration='@action=set_allow @src_ip=all @method=GET @method=POST',
    named_acls=[],
    expected_responses=[200, 200, 403, 403, 403],
    proxy_protocol=False)

test_ip_allow_optional_methods = Test_remap_acl(
    "Verify @src_ip_category works.",
    replay_file='remap_acl_get_post_allowed.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=False,
    acl_behavior_policy=1,
    acl_configuration='@action=set_allow @src_ip_category=ACME_LOCAL @method=GET @method=POST',
    named_acls=[],
    expected_responses=[200, 200, 403, 403, 403],
    proxy_protocol=False)

test_ip_allow_optional_methods = Test_remap_acl(
    "Verify no @src_ip implies all IP addresses.",
    replay_file='remap_acl_get_post_allowed.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=False,
    acl_behavior_policy=1,
    acl_configuration='@action=set_allow @method=GET @method=POST',
    named_acls=[],
    expected_responses=[200, 200, 403, 403, 403],
    proxy_protocol=False)

test_ip_allow_optional_methods = Test_remap_acl(
    "Verify denied methods are blocked.",
    replay_file='remap_acl_get_post_denied.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=False,
    acl_behavior_policy=1,
    acl_configuration='@action=set_deny @src_ip=127.0.0.1 @method=GET @method=POST',
    named_acls=[],
    expected_responses=[403, 403, 200, 200, 400],
    proxy_protocol=False)

test_ip_allow_optional_methods = Test_remap_acl(
    "Verify add_deny adds blocked methods.",
    replay_file='remap_acl_all_denied.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=False,
    acl_behavior_policy=1,
    acl_configuration='@action=add_deny @src_ip=127.0.0.1 @method=GET',
    named_acls=[],
    expected_responses=[403, 403, 403, 403, 403],
    proxy_protocol=False)

test_ip_allow_optional_methods = Test_remap_acl(
    "Verify a default deny filter rule works.",
    replay_file='remap_acl_all_denied.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=False,
    acl_behavior_policy=1,
    acl_configuration='@action=set_allow @src_ip=1.2.3.4 @method=GET @method=POST',
    named_acls=[('deny', '@action=set_deny')],
    expected_responses=[403, 403, 403, 403, 403],
    proxy_protocol=False)

test_ip_allow_optional_methods = Test_remap_acl(
    "Verify inverting @src_ip works.",
    replay_file='remap_acl_all_denied.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=False,
    acl_behavior_policy=1,
    acl_configuration='@action=set_allow @src_ip=~127.0.0.1 @method=GET @method=POST',
    named_acls=[('deny', '@action=set_deny')],
    expected_responses=[403, 403, 403, 403, 403],
    proxy_protocol=False)

test_ip_allow_optional_methods = Test_remap_acl(
    "Verify inverting @src_ip works with the rule matching.",
    replay_file='remap_acl_get_post_allowed.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=False,
    acl_behavior_policy=1,
    acl_configuration='@action=set_allow @src_ip=~3.4.5.6 @method=GET @method=POST',
    named_acls=[('deny', '@action=set_deny')],
    expected_responses=[200, 200, 403, 403, 403],
    proxy_protocol=False)

test_ip_allow_optional_methods = Test_remap_acl(
    "Verify inverting @src_ip_category works.",
    replay_file='remap_acl_all_denied.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=False,
    acl_behavior_policy=1,
    acl_configuration='@action=set_allow @src_ip_category=~ACME_LOCAL @method=GET @method=POST',
    named_acls=[('deny', '@action=set_deny')],
    expected_responses=[403, 403, 403, 403, 403],
    proxy_protocol=False)

test_ip_allow_optional_methods = Test_remap_acl(
    "Verify inverting @src_ip_category works with the rule matching.",
    replay_file='remap_acl_get_post_allowed.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=False,
    acl_behavior_policy=1,
    acl_configuration='@action=set_allow @src_ip_category=~ACME_EXTERNAL @method=GET @method=POST',
    named_acls=[('deny', '@action=set_deny')],
    expected_responses=[200, 200, 403, 403, 403],
    proxy_protocol=False)

test_ip_allow_optional_methods = Test_remap_acl(
    "Verify @src_ip and @src_ip_category AND together.",
    replay_file='remap_acl_all_denied.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=False,
    acl_behavior_policy=1,
    # The rule will not match because, while @src_ip matches, @src_ip_category does not.
    acl_configuration='@action=set_allow @src_ip=127.0.0.1 @src_ip_category=ACME_EXTERNAL @method=GET @method=POST',
    # Therefore, this named deny filter will block.
    named_acls=[('deny', '@action=set_deny')],
    expected_responses=[403, 403, 403, 403, 403],
    proxy_protocol=False)

test_ip_allow_optional_methods = Test_remap_acl(
    "Verify defined in-line ACLS are evaluated before named ones.",
    replay_file='remap_acl_get_post_allowed.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=False,
    acl_behavior_policy=1,
    acl_configuration='@action=set_allow @src_ip=127.0.0.1 @method=GET @method=POST',
    named_acls=[('deny', '@action=set_deny')],
    expected_responses=[200, 200, 403, 403, 403],
    proxy_protocol=False)

test_ip_allow_optional_methods = Test_remap_acl(
    "Verify remap.config line overrides ip_allow rule.",
    replay_file='remap_acl_get_post_allowed.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=False,
    acl_behavior_policy=1,
    acl_configuration='@action=set_allow @src_ip=127.0.0.1 @method=GET @method=POST',
    named_acls=[],
    expected_responses=[200, 200, 403, 403, 403],
    proxy_protocol=False)

test_ip_allow_optional_methods = Test_remap_acl(
    "Verify we can deactivate the ip_allow filter.",
    replay_file='remap_acl_all_allowed.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=True,
    acl_behavior_policy=1,
    # This won't match, so nothing will match since ip_allow.yaml is off.
    acl_configuration='@action=set_allow @src_ip=1.2.3.4 @method=GET @method=POST',
    named_acls=[],
    # Nothing will block the request since ip_allow.yaml is off.
    expected_responses=[200, 200, 200, 200, 400],
    proxy_protocol=False)

test_ip_allow_optional_methods = Test_remap_acl(
    "Verify in_ip matches on IP as expected.",
    replay_file='remap_acl_get_post_allowed.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=False,
    acl_behavior_policy=1,
    acl_configuration='@action=set_allow @in_ip=127.0.0.1 @method=GET @method=POST',
    named_acls=[],
    expected_responses=[200, 200, 403, 403, 403],
    proxy_protocol=False)

test_ip_allow_optional_methods = Test_remap_acl(
    "Verify in_ip rules do not match on other IPs.",
    replay_file='remap_acl_get_allowed.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=False,
    acl_behavior_policy=1,
    acl_configuration='@action=set_allow @in_ip=3.4.5.6 @method=GET @method=POST',
    named_acls=[],
    expected_responses=[200, 403, 403, 403, 403],
    proxy_protocol=False)

test_named_acl_deny = Test_remap_acl(
    "Verify a named ACL is applied if an in-line ACL is absent.",
    replay_file='deny_head_post.replay.yaml',
    ip_allow_content=IP_ALLOW_CONTENT,
    deactivate_ip_allow=False,
    acl_behavior_policy=1,
    acl_configuration='',
    named_acls=[('deny', '@action=set_deny @method=HEAD @method=POST')],
    expected_responses=[200, 403, 403, 403],
    proxy_protocol=False)


def replay_proxy_response(filename, replay_file, get_proxy_response, post_proxy_response):
    """
    replay_proxy_response writes the given replay file (which expects a single GET & POST client-request)
    with the given proxy_response value. This is only used to support the tests in the combination table.
    """

    current_dir = os.path.dirname(inspect.getfile(inspect.currentframe()))
    path = os.path.join(current_dir, filename)
    data = None
    with open(path) as f:
        data = load(f, Loader=Loader)
        for session in data["sessions"]:
            for transaction in session["transactions"]:
                method = transaction["client-request"]["method"]
                if method == "GET":
                    transaction["proxy-response"]["status"] = 403 if get_proxy_response == None else get_proxy_response
                elif method == "POST":
                    transaction["proxy-response"]["status"] = 403 if post_proxy_response == None else post_proxy_response
                else:
                    raise Exception("Expected to find GET or POST request, found %s", method)
    with open(replay_file, "w") as f:
        f.write(dump(data))


from deactivate_ip_allow import all_deactivate_ip_allow_tests
from all_acl_combinations import all_acl_combination_tests
from collections import defaultdict
import copy


def group_tests_by_bucket(all_tests):
    """
    Group tests by everything except acl_configuration and expected_responses.
    Returns a dict: bucket_key -> list of test dicts
    """
    buckets = defaultdict(list)
    for test in all_tests:
        # Build key of fields that must match to be groupable
        named_acl_key = test.get("named_acl", "")
        if isinstance(named_acl_key, str):
            named_acl_key = tuple(sorted(named_acl_key.splitlines())) if named_acl_key else ()
        else:
            named_acl_key = tuple(named_acl_key) if named_acl_key else ()
        
        # Check if this test expects connection rejection (None responses)
        has_none_response = (test.get("GET response") is None and test.get("POST response") is None)
            
        key = (
            test.get("ip_allow", ""), 
            test.get("policy", ""), 
            named_acl_key,
            test.get("deactivate_ip_allow", False),
            has_none_response,  # Add this to prevent mixing None and non-None response tests
        )
        buckets[key].append(test)
    return buckets


def create_grouped_replay_file(bucket_tests, base_replay_path):
    """
    Create a replay file that has requests for multiple remap paths.
    - bucket_tests: list of test dicts that are groupable
    - base_replay_path: path to base.replay.yaml
    Returns: (replay_path, case_infos)
    case_infos: list of dicts { path: '/acl_case_X/', acl_configuration: '...', expected_responses: [...]}
    """
    case_infos = []
    
    # Load the base replay file
    current_dir = os.path.dirname(inspect.getfile(inspect.currentframe()))
    base_path = os.path.join(current_dir, base_replay_path)
    
    data = None
    with open(base_path) as f:
        data = load(f, Loader=Loader)
    
    # Create new sessions for each test case
    original_session = data["sessions"][0]  # Use the first session as template
    new_sessions = []
    
    for idx, test in enumerate(bucket_tests):
        path = "/acl_case_{}/".format(idx)
        case_infos.append({
            "path": path,
            "acl_configuration": test.get("inline", ""),
            "expected_responses": [test.get("GET response"), test.get("POST response")],
        })
        
        # Create a new session for this test case by copying the original
        new_session = copy.deepcopy(original_session)
        
        # Update URLs and expected responses for each transaction in this session
        for transaction in new_session["transactions"]:
            method = transaction["client-request"]["method"]
            # Update the URL path
            old_url = transaction["client-request"]["url"]
            new_url = path + old_url.lstrip('/')
            transaction["client-request"]["url"] = new_url
            
            # Update expected proxy response based on test expectations
            if method == "GET":
                expected_status = test.get("GET response")
            elif method == "POST":
                expected_status = test.get("POST response")
            else:
                expected_status = 403  # Default fallback
                
            if expected_status is not None:
                transaction["proxy-response"]["status"] = expected_status
            else:
                # For None responses, we still need a status but it won't be used
                # since the connection should be rejected at the IP allow level
                transaction["proxy-response"]["status"] = 403
        
        new_sessions.append(new_session)
    
    # Create new data structure with all sessions
    new_data = copy.deepcopy(data)
    new_data["sessions"] = new_sessions
    
    # Write to a new temporary file
    fd, replay_file_path = tempfile.mkstemp(suffix="_grouped.replay.yaml")
    os.close(fd)
    
    with open(replay_file_path, "w") as f:
        f.write(dump(new_data))
    
    return replay_file_path, case_infos


class Test_remap_acl_Grouped:
    """Configure a grouped test to verify multiple remap.config acl behaviors in a single ATS instance."""

    _ts_counter: int = 0
    _server_counter: int = 0
    _client_counter: int = 0

    def __init__(self, name: str, bucket_tests: list, base_replay_file: str):
        """Initialize the grouped test.

        :param name: The name of the test group.
        :param bucket_tests: List of test configurations that share common parameters.
        :param base_replay_file: The base replay file to be used as template.
        """
        self._bucket_tests = bucket_tests
        
        # All tests in the bucket should have identical non-ACL parameters
        first_test = bucket_tests[0]
        self._ip_allow_content = first_test["ip_allow"]
        self._deactivate_ip_allow = first_test.get("deactivate_ip_allow", False)
        self._acl_behavior_policy = 0 if first_test["policy"] == "legacy" else 1
        self._named_acls = [("acl", first_test["named_acl"])] if first_test["named_acl"] != "" else []
        self._proxy_protocol = False  # All current test cases use False

        # Generate grouped replay file and case info
        self._replay_file, self._case_infos = create_grouped_replay_file(bucket_tests, base_replay_file)

        tr = Test.AddTestRun(name)
        self._configure_server(tr)
        self._configure_traffic_server(tr)
        self._configure_client(tr)

    def _configure_server(self, tr: 'TestRun') -> None:
        """Configure the server.

        :param tr: The TestRun object to associate the server process with.
        """
        name = f"server-grouped-{Test_remap_acl_Grouped._server_counter}"
        server = tr.AddVerifierServerProcess(name, self._replay_file)
        Test_remap_acl_Grouped._server_counter += 1
        self._server = server

    def _configure_traffic_server(self, tr: 'TestRun') -> None:
        """Configure Traffic Server.

        :param tr: The TestRun object to associate the Traffic Server process with.
        """
        name = f"ts-grouped-{Test_remap_acl_Grouped._ts_counter}"
        ts = tr.MakeATSProcess(name, enable_cache=False, enable_proxy_protocol=self._proxy_protocol, enable_uds=False)
        Test_remap_acl_Grouped._ts_counter += 1
        self._ts = ts

        ts.Disk.records_config.update(
            {
                'proxy.config.diags.debug.enabled': 1,
                'proxy.config.diags.debug.tags': 'http|url|remap|ip_allow|proxyprotocol',
                'proxy.config.http.push_method_enabled': 1,
                'proxy.config.http.connect_ports': self._server.Variables.http_port,
                'proxy.config.url_remap.acl_behavior_policy': self._acl_behavior_policy,
                'proxy.config.acl.subjects': 'PROXY,PEER',
            })

        remap_config_lines = []
        if self._deactivate_ip_allow:
            remap_config_lines.append('.deactivatefilter ip_allow')

        # First, define the named ACLs (filters).
        for name, definition in self._named_acls:
            remap_config_lines.append(f'.definefilter {name} {definition}')
        # Now activate them.
        for name, _ in self._named_acls:
            remap_config_lines.append(f'.activatefilter {name}')

        # Create multiple remap rules - one for each test case in the bucket
        for case_info in self._case_infos:
            path = case_info["path"]
            acl_config = case_info["acl_configuration"]
            remap_line = f'map {path} http://127.0.0.1:{self._server.Variables.http_port} {acl_config}'
            remap_config_lines.append(remap_line)

        ts.Disk.remap_config.AddLines(remap_config_lines)
        ts.Disk.ip_allow_yaml.AddLines(self._ip_allow_content.split("\n"))

    def _configure_client(self, tr: 'TestRun') -> None:
        """Run the test.

        :param tr: The TestRun object to associate the client process with.
        """
        name = f"client-grouped-{Test_remap_acl_Grouped._client_counter}"
        port = self._ts.Variables.port if self._proxy_protocol == False else self._ts.Variables.proxy_protocol_port
        p = tr.AddVerifierClientProcess(name, self._replay_file, http_ports=[port])
        Test_remap_acl_Grouped._client_counter += 1
        p.StartBefore(self._server)
        p.StartBefore(self._ts)

        # Build expected response pattern for all test cases in sequence
        all_expected_responses = []
        has_none_responses = False
        
        for case_info in self._case_infos:
            expected_responses = case_info["expected_responses"]
            if expected_responses == [None, None]:
                has_none_responses = True
                break
            all_expected_responses.extend([str(code) for code in expected_responses])

        if has_none_responses:
            # If any test cases expect connection rejection, expect the Warning about the rejected ip.
            self._ts.Disk.diags_log.Content += Testers.ContainsExpression(
                "client '127.0.0.1' prohibited by ip-allow policy", "Verify the client rejection warning message.")
            # Also, the client will complain about the broken connections.
            p.ReturnCode = 1
        else:
            p.Streams.stdout += Testers.ContainsExpression(
                '.*'.join(all_expected_responses), "Verifying the expected order of responses for grouped tests", reflags=re.DOTALL | re.MULTILINE)


"""
Test all acl combinations - OPTIMIZED with grouping
"""
acl_buckets = group_tests_by_bucket(all_acl_combination_tests)

for bucket_idx, (bucket_key, bucket_tests) in enumerate(acl_buckets.items()):
    if len(bucket_tests) == 1:
        # Keep legacy handling for singletons (no change)
        test = bucket_tests[0]
        (_, replay_file_name) = tempfile.mkstemp(suffix="acl_table_test_single_{}.replay".format(test["index"]))
        replay_proxy_response(
            "base.replay.yaml",
            replay_file_name,
            test["GET response"],
            test["POST response"],
        )
        Test_remap_acl(
            "allcombo-{0} {1} {2} {3}".format(test["index"], test["inline"], test["named_acl"], test["ip_allow"]),
            replay_file=replay_file_name,
            ip_allow_content=test["ip_allow"],
            deactivate_ip_allow=False,
            acl_behavior_policy=0 if test["policy"] == "legacy" else 1,
            acl_configuration=test["inline"],
            named_acls=[("acl", test["named_acl"])] if test["named_acl"] != "" else [],
            expected_responses=[test["GET response"], test["POST response"]],
            proxy_protocol=False,
        )
    else:
        # Grouped path - multiple test cases in one ATS instance
        test_indices = [t["index"] for t in bucket_tests]
        group_name = "allcombo-grouped-bucket-{}-tests-{}".format(bucket_idx, "-".join(map(str, test_indices)))
        
        Test_remap_acl_Grouped(
            group_name,
            bucket_tests,
            "base.replay.yaml"
        )
"""
Test all ACL combinations with deactivate_ip_allow - OPTIMIZED with grouping
"""
deactivate_buckets = group_tests_by_bucket(all_deactivate_ip_allow_tests)

for bucket_idx, (bucket_key, bucket_tests) in enumerate(deactivate_buckets.items()):
    if len(bucket_tests) == 1:
        # Keep legacy handling for singletons (no change)
        test = bucket_tests[0]
        try:
            test["deactivate_ip_allow"]
        except:
            print(test)
        (_, replay_file_name) = tempfile.mkstemp(suffix="deactivate_ip_allow_table_test_single_{}.replay".format(test["index"]))
        replay_proxy_response(
            "base.replay.yaml",
            replay_file_name,
            test["GET response"],
            test["POST response"],
        )
        Test_remap_acl(
            "ipallow-{0} {1} {2} {3}".format(test["index"], test["inline"], test["named_acl"], test["ip_allow"]),
            replay_file=replay_file_name,
            ip_allow_content=test["ip_allow"],
            deactivate_ip_allow=test["deactivate_ip_allow"],
            acl_behavior_policy=0 if test["policy"] == "legacy" else 1,
            acl_configuration=test["inline"],
            named_acls=[("acl", test["named_acl"])] if test["named_acl"] != "" else [],
            expected_responses=[test["GET response"], test["POST response"]],
            proxy_protocol=False,
        )
    else:
        # Grouped path - multiple test cases in one ATS instance
        test_indices = [t["index"] for t in bucket_tests]
        group_name = "ipallow-grouped-bucket-{}-tests-{}".format(bucket_idx, "-".join(map(str, test_indices)))
        
        Test_remap_acl_Grouped(
            group_name,
            bucket_tests,
            "base.replay.yaml"
        )
