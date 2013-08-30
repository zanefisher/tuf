"""
<Program Name>
  aggregate_system_tests.py

<Author>
  Zane Fisher

<Started>
  July 21, 2013
 
<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Run all tests in 'tuf/tests/system_tests'.

"""

import test_util_test_tools
import slow_retrieval_server

import test_arbitrary_package_attack
import test_delegations
import test_endless_data_attack
import test_extraneous_dependencies_attack
import test_mix_and_match_attack
import test_replay_attack
import test_slow_retrieval_attack
import test_indefinite_freeze_attack
