"""
<Program Name>
  roledb.py

<Author>
  Vladimir Diaz <vladimir.v.diaz@gmail.com>

<Started>
  March 21, 2012.  Based on a previous version of this module by Geremy Condra.
  
<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Represent a collection of roles and their organization.  The caller may create
  a collection of roles from those found in the 'root.json' metadata file by
  calling 'create_roledb_from_rootmeta()', or individually by adding roles with
  'add_role()'.  There are many supplemental functions included here that yield
  useful information about the roles contained in the database, such as
  extracting all the parent rolenames for a specified rolename, deleting all the
  delegated roles, retrieving role paths, etc.  The Update Framework process
  maintains a single roledb.

  The role database is a dictionary conformant to 'tuf.formats.ROLEDICT_SCHEMA'
  and has the form:
  
  {'rolename': {'keyids': ['34345df32093bd12...'],
                'threshold': 1
                'signatures': ['abcd3452...'],
                'paths': ['path/to/role.json'],
                'path_hash_prefixes': ['ab34df13'],
                'delegations': {'keys': {}, 'roles': {}}}
  
  The 'name', 'paths', 'path_hash_prefixes', and 'delegations' dict keys are
  optional.
"""

# Help with Python 3 compatibility, where the print statement is a function, an
# implicit relative import is invalid, and the '/' operator performs true
# division.  Example:  print 'hello world' raises a 'SyntaxError' exception.
from __future__ import print_function
from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import logging
import copy

import tuf
import tuf.formats
import tuf.log
import tuf._vendor.six as six

# See 'tuf.log' to learn how logging is handled in TUF.
logger = logging.getLogger('tuf.roledb')

# The role database.
_roledb_dict = {}

_track_changes = False

# A dict of all roles' unwritten changes.
_unwritten_role_changes = {}

# Which roles do not have the required number of signatures as of the latest write.
_partially_written_rolenames = set()


def create_roledb_from_root_metadata(root_metadata, track_changes=False):
  """
  <Purpose>
    Create a role database containing all of the unique roles found in
    'root_metadata'.

  <Arguments>
    root_metadata:
      A dictionary conformant to 'tuf.formats.ROOT_SCHEMA'.  The roles found
      in the 'roles' field of 'root_metadata' is needed by this function.  

    track_changes:
      If True, the roledb will keep track of all unwritten changes to the roles.

  <Exceptions>
    tuf.FormatError, if 'root_metadata' does not have the correct object format.

    tuf.Error, if one of the roles found in 'root_metadata' contains an invalid
    delegation (i.e., a nonexistent parent role).

  <Side Effects>
    Calls add_role().
    
    The old role database is replaced.

  <Returns>
    None.
  """

  _track_changes = track_changes

  # Does 'root_metadata' have the correct object format?
  # This check will ensure 'root_metadata' has the appropriate number of objects 
  # and object types, and that all dict keys are properly named.
  # Raises tuf.FormatError.
  tuf.formats.ROOT_SCHEMA.check_match(root_metadata)

  # Clear the role database.
  _roledb_dict.clear()

  # Do not modify the contents of the 'root_metadata' argument.
  root_metadata = copy.deepcopy(root_metadata)
  
  # Iterate through the roles found in 'root_metadata'
  # and add them to '_roledb_dict'.  Duplicates are avoided.
  for rolename, roleinfo in six.iteritems(root_metadata['roles']):
    if rolename == 'root':
      roleinfo['version'] = root_metadata['version']
      roleinfo['expires'] = root_metadata['expires']
    
    roleinfo['signatures'] = []
    roleinfo['signing_keyids'] = []
    roleinfo['compressions'] = ['']
    roleinfo['partial_loaded'] = False
    if rolename.startswith('targets'):
      roleinfo['paths'] = {}
      roleinfo['delegations'] = {'keys': {}, 'roles': []}
    
    try:
      add_role(rolename, roleinfo)
    # tuf.Error raised if the parent role of 'rolename' does not exist.  
    except tuf.Error as e:
      logger.error(e)
      raise





def add_role(rolename, roleinfo, require_parent=True):
  """
  <Purpose>
    Add to the role database the 'roleinfo' associated with 'rolename'.

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'snapshot', 'timestamp').

    roleinfo:
      An object representing the role associated with 'rolename', conformant to
      ROLEDB_SCHEMA.  'roleinfo' has the form: 
      {'keyids': ['34345df32093bd12...'],
       'threshold': 1,
       'signatures': ['ab23dfc32']
       'paths': ['path/to/target1', 'path/to/target2', ...],
       'path_hash_prefixes': ['a324fcd...', ...],
       'delegations': {'keys': }

      The 'paths', 'path_hash_prefixes', and 'delegations' dict keys are
      optional.
      
      The 'target' role has an additional 'paths' key.  Its value is a list of
      strings representing the path of the target file(s).

    require_parent:
      A boolean indicating whether to check for a delegating role.  add_role()
      will raise an exception if this parent role does not exist.

  <Exceptions>
    tuf.FormatError, if 'rolename' or 'roleinfo' does not have the correct
    object format.

    tuf.RoleAlreadyExistsError, if 'rolename' has already been added.

    tuf.InvalidNameError, if 'rolename' is improperly formatted.

  <Side Effects>
    The role database is modified.

  <Returns>
    None.
  """

  # Does 'rolename' have the correct object format?
  # This check will ensure 'rolename' has the appropriate number of objects 
  # and object types, and that all dict keys are properly named.
  tuf.formats.ROLENAME_SCHEMA.check_match(rolename)

  # Does 'roleinfo' have the correct object format?
  tuf.formats.ROLEDB_SCHEMA.check_match(roleinfo)

  # Does 'require_parent' have the correct format?
  tuf.formats.BOOLEAN_SCHEMA.check_match(require_parent)

  # Raises tuf.InvalidNameError.
  _validate_rolename(rolename)

  if rolename in _roledb_dict:
    raise tuf.RoleAlreadyExistsError('Role already exists: '+rolename)

  # Make sure that the delegating role exists. This should be just a
  # sanity check and not a security measure.
  if require_parent and '/' in rolename:
    # Get parent role.  'a/b/c/d' --> 'a/b/c'. 
    parent_role = '/'.join(rolename.split('/')[:-1])

    if parent_role not in _roledb_dict:
      raise tuf.Error('Parent role does not exist: '+parent_role)

  _roledb_dict[rolename] = copy.deepcopy(roleinfo)

  _unwritten_role_changes[rolename] = {created: True, touched: False}


def _generate_role_changes_entry(created):
  return {'created': created,
          'touched': False,
          'targets_added': [],
          'targets_removed': [],
          'delegations_made': [],
          'delegations_removed': [],
          'delegation_keys_added': {},
          'delegation_keys_revoked': {},
          'delegation_thresholds_modified': {},
          'delegation_paths_added': {},
          'delegation_paths_removed': {},
          'delegation_path_hash_prefixes_added': {},
          'delegation_path_hash_prefixes_removed': {}}


def _modify_changes_list(changes_list, list_to_add, list_to_remove):
  changes_list = list((set(changes_list) + set(list_to_add)) \
                              - set(list_to_remove))

def _retrieve_list_from_dict(given_dict, key):
  if given_dict in key:
    if isinstance(given_dict[key], list)
      return given_dict[key]
    else:
      return list(given_dict[key])
  else:
    return []


def _update_unwritten_role_changes(rolename, new_roleinfo):

  if rolename in _unwritten_role_changes:
    changes = _unwritten_role_changes[rolename]
  else:
    changes = _generate_role_changes_entry(created=False)

  previous_roleinfo = _roledb_dict[rolename]


  # Record changes to targets.
  previous_paths = _retrieve_list_from_dict(previous_roleinfo, 'paths')
  new_paths = _retrieve_list_from_dict(new_roleinfo, 'paths')

  _modify_changes_list(changes['targets_added'], new_paths, previous_paths)
  _modify_changes_list(changes['targets_removed'], previous_paths, new_paths)


  # Record created and revoked delegations.
  previous_delegated_rolenames = previous_roleinfo['delegations']['roles'].keys()

  new_delegated_rolenames = new_roleinfo['delegations']['roles'].keys()

  _modify_changes_list(changes['delegations_made'], 
        new_delegated_rolenames, previous_delegated_rolenames)

  _modify_changes_list(changes['delegations_revoked'],
        previous_delegated_rolenames, new_delegated_rolenames)

  # Record changes to delegations. Changes to delegations slated to be revoked
  # are maintained until the revokation is written.
  all_delegated_rolenames = list(set(previous_delegated_rolenames) + \
                                  set(new_delegated_rolenames))

  for delegated_rolename in all_delegated_rolenames:
    previous_delegated_role = previous_roleinfo['delegations']['roles'][delegated_rolename]
    new_delegated_role = new_roleinfo['delegations']['roles'][delegated_rolename]

    # Record added and revoked keys.
    previous_keys = _retrieve_list_from_dict(previous_delegated_role, 'keyids')
    new_keys = _retrieve_list_from_dict(new_delegated_role, 'keyids')
    _modify_changes_list(changes['keys_added'][delegated_rolename], new_keys, previous_keys)
    _modify_changes_list(changes['keys_revoked'][delegated_rolename], previous_keys, new_keys)

    # Record added and removed paths.
    previous_paths = _retrieve_list_from_dict(previous_delegated_role, 'paths')
    new_paths = _retrieve_list_from_dict(new_delegated_role, 'paths')
    _modify_changes_list(changes['paths_added'][delegated_rolename], new_paths, previous_paths)
    _modify_changes_list(changes['paths_removed'][delegated_rolename], previous_paths, new_paths)

    # Record added and removed path has prefixes.
    previous_prefixes = _retrieve_list_from_dict(previous_delegated_role, 'path_hash_prefixes')
    new_prefixes = _retrieve_list_from_dict(new_delegated_role, 'path_hash_prefixes')
    _modify_changes_list(changes['delegation_path_hash_prefixes_added'][delegated_rolename], new_prefixes, previous_prefixes)
    _modify_changes_list(changes['delegation_path_hash_prefixes_removed'][delegated_rolename], previous_prefixes, new_prefixes)

    # Record changes to thresholds
    threshold_diff = new_delegated_role['threshold'] - previous_delegated_role['threshold']
    changes['delegation_thresholds_modified'][delegated_rolename] += threshold_diff


  if changes == _generate_role_changes_entry(created=False):
    del _unwritten_role_changes[rolename]

  else:
    _unwritten_role_changes[rolename] = changes


def update_roleinfo(rolename, roleinfo):
  """
  <Purpose>

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'snapshot', 'timestamp').

    roleinfo:
      An object representing the role associated with 'rolename', conformant to
      ROLEDB_SCHEMA.  'roleinfo' has the form: 
      {'name': 'role_name',
       'keyids': ['34345df32093bd12...'],
       'threshold': 1,
       'paths': ['path/to/target1', 'path/to/target2', ...],
       'path_hash_prefixes': ['a324fcd...', ...]}

      The 'name', 'paths', and 'path_hash_prefixes' dict keys are optional.

      The 'target' role has an additional 'paths' key.  Its value is a list of
      strings representing the path of the target file(s).

  <Exceptions>
    tuf.FormatError, if 'rolename' or 'roleinfo' does not have the correct
    object format.

    tuf.UnknownRoleError, if 'rolename' cannot be found in the role database.
    
    tuf.InvalidNameError, if 'rolename' is improperly formatted.

  <Side Effects>
    The role database is modified.

  <Returns>
    None.
  """

  # Does 'rolename' have the correct object format?
  # This check will ensure 'rolename' has the appropriate number of objects 
  # and object types, and that all dict keys are properly named.
  tuf.formats.ROLENAME_SCHEMA.check_match(rolename)

  # Does 'roleinfo' have the correct object format?
  tuf.formats.ROLEDB_SCHEMA.check_match(roleinfo)

  # Raises tuf.InvalidNameError.
  _validate_rolename(rolename)

  if rolename not in _roledb_dict:
    raise tuf.UnknownRoleError('Role does not exist: '+rolename)

  # Record the changes and update the role.
  if _track_changes:
    _update_unwritten_role_changes(rolename, roleinfo)

  _roledb_dict[rolename] = copy.deepcopy(roleinfo)


def signature_count_on_write(rolename):

  _check_rolename(rolename)

  signing_keyids = set(_roledb_dict[rolename]['signing_keyids'])
  delegation = _roledb_dict[get_parent_rolename(rolename)]['delegations'][rolename]
  delegated 


  if rolename in _unwritten_role_changes.keys()

    # If changes have been made, the old signatures will be removed,
    # the sigining keys will be used to make new signatures.
    return len(signing_keyids)

  else:

    signed_keyids = set(sig['keyid'] for sig in \
                              _roledb_dict[rolename]['signatures'])

    # If the role is partially signed and no changes have been made, any
    # signing keys that have not signed the role will do so.
    if len(signed_keyids) < threshold:
      return len(signing_keyids + signed_keyids)

    # If no changes have been made, and no new signatures are needed for a
    # full write, no new signatures.
    else:
      return len(signed_keyids)



def list_changed_rolenames():
  return _unwritten_role_changes.keys()


def list_incomplete_unchanged_rolenames():
  assert _track_changes

  incomplete_unchanged_rolenames = [] 
  dirty_rolenames = _unwritten_role_changes.keys()

  # Append all partially written unchanged roles.
  for rolename in _partially_written_rolenames:
    if rolename not in dirty_rolenames:
      incomplete_unchanged_rolenames.append(rolename)


  # Append any unchanged role whose parent's changes will cause it to become
  # incomplete. Ignore roles already in the list.
  for parent_rolename in dirty_rolenames:
    for delegation in _roledb_dict[parent_rolename]['delegations']['roles'].values()
      if delegation['name'] not in _partially_written_rolenames:

        delegated_role = _roledb_dict[delegation['name']]
        valid_keyids = set(delegation['keyids'])
        signed_keyids = set(sig['keyid'] for sig in delegated_role['signatures'])
        valid_signature_count = len(valid_keyids.intersection(signed_keyids))

        if valid_signature_count < delegation['threshold']:
          incomplete_unchanged_rolenames.add(delegated_role['name'])

  return incomplete_unchanged_rolenames


def touch_role(rolename, value=True):
  assert _track_changes

  if rolename not in _unwritten_role_changes.keys():
    if value == False:
      return
    else:
      _unwritten_role_changes[rolename] = _generate_role_changes_entry(created=False)

  _unwritten_role_changes[rolename]['touched'] = value


def clear_unwritten_changes_after_write():
  _unwritten_role_changes = {}


def set_partially_written_rolenames(rolename_set):
  _partially_written_rolenames


def get_parent_rolename(rolename):
  """
  <Purpose>
    Return the name of the parent role for 'rolename'.
    Given the rolename 'a/b/c/d', return 'a/b/c'.
    Given 'a', return ''.

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'snapshot', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' does not have the correct object format.

    tuf.UnknownRoleError, if 'rolename' cannot be found in the role database.

    tuf.InvalidNameError, if 'rolename' is incorrectly formatted.

  <Side Effects>
    None.

  <Returns>
    A string representing the name of the parent role.
  """

  # Raises tuf.FormatError, tuf.UnknownRoleError, or tuf.InvalidNameError.
  _check_rolename(rolename)

  parts = rolename.split('/')
  parent_rolename = '/'.join(parts[:-1])

  return parent_rolename





def get_all_parent_roles(rolename):
  """
  <Purpose>
    Return a list of roles that are parents of 'rolename'.
    Given the rolename 'a/b/c/d', return the list:
    ['a', 'a/b', 'a/b/c'].

    Given 'a', return ['a'].
  
  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'snapshot', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' does not have the correct object format. 

    tuf.UnknownRoleError, if 'rolename' cannot be found in the role database.

    tuf.InvalidNameError, if 'rolename' is improperly formatted.

  <Side Effects>
    None.

  <Returns>
    A list containing all the parent roles.
  """
    
  # Raises tuf.FormatError, tuf.UnknownRoleError, or tuf.InvalidNameError.
  _check_rolename(rolename)

  # List of parent roles returned.
  parent_roles = []

  parts = rolename.split('/')

  # Append the first role to the list.
  parent_roles.append(parts[0])

  # The 'roles_added' string contains the roles already added.  If 'a' and 'a/b'
  # have been added to 'parent_roles', 'roles_added' would contain 'a/b'
  roles_added = parts[0]

  # Add each subsequent role to the previous string (with a '/' separator).
  # This only goes to -1 because we only want to return the parents (so we
  # ignore the last element).
  for next_role in parts[1:-1]:
    parent_roles.append(roles_added+'/'+next_role)
    roles_added = roles_added+'/'+next_role

  return parent_roles





def role_exists(rolename):
  """
  <Purpose>
    Verify whether 'rolename' is stored in the role database.

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'snapshot', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' does not have the correct object format.

    tuf.InvalidNameError, if 'rolename' is incorrectly formatted.

  <Side Effects>
    None.

  <Returns>
    Boolean.  True if 'rolename' is found in the role database, False otherwise.
  """

  # Raise tuf.FormatError, tuf.InvalidNameError.
  try: 
    _check_rolename(rolename)
  except (tuf.FormatError, tuf.InvalidNameError):
    raise
  except tuf.UnknownRoleError:
    return False
  
  return True





def remove_role(rolename):
  """
  <Purpose>
    Remove 'rolename', including its delegations.

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'snapshot', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' does not have the correct object format.

    tuf.UnknownRoleError, if 'rolename' cannot be found in the role database.

    tuf.InvalidNameError, if 'rolename' is incorrectly formatted.

  <Side Effects>
    A role, or roles, may be removed from the role database.

  <Returns>
    None.
  """
 
  # Raises tuf.FormatError, tuf.UnknownRoleError, or tuf.InvalidNameError.
  _check_rolename(rolename)
  
  remove_delegated_roles(rolename)
 
  # remove_delegated_roles() should have left 'rolename' in the database, and
  # 'rolename' was verified to exist by _check_rolename().
  # Remove 'rolename'.
  del _roledb_dict[rolename]





def remove_delegated_roles(rolename):
  """
  <Purpose>
    Remove a role's delegations (leaving the rest of the role alone).
    All levels of delegation are removed, not just the directly delegated roles.
    If 'rolename' is 'a/b/c' and the role database contains
    ['a/b/c/d/e', 'a/b/c/d', 'a/b/c', 'a/b', 'a'], return
    ['a/b/c', 'a/b', 'a'].

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'snapshot', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' does not have the correct object format. 
   
    tuf.UnknownRoleError, if 'rolename' cannot be found in the role database.

    tuf.InvalidNameError, if 'rolename' is incorrectly formatted.

  <Side Effects>
    Role(s) from the role database may be deleted.

  <Returns>
    None.
  """
  
  # Raises tuf.FormatError, tuf.UnknownRoleError, or tuf.InvalidNameError.
  _check_rolename(rolename)

  # Ensure that we only care about delegated roles!
  rolename_with_slash = rolename + '/'
  for name in get_rolenames():
    if name.startswith(rolename_with_slash):
      del _roledb_dict[name]





def get_rolenames():
  """
  <Purpose>
    Return a list of the rolenames found in the role database.

  <Arguments>
    None.

  <Exceptions>
    None.

  <Side Effects>
    None.
  
  <Returns>
    A list of rolenames.
  """
  
  return list(_roledb_dict.keys())





def get_roleinfo(rolename):
  """
  <Purpose>
    Return the roleinfo of 'rolename'.

    {'keyids': ['34345df32093bd12...'],
     'threshold': 1,
     'signatures': ['ab453bdf...', ...],
     'paths': ['path/to/target1', 'path/to/target2', ...],
     'path_hash_prefixes': ['a324fcd...', ...],
     'delegations': {'keys': {}, 'roles': []}}

    The 'signatures', 'paths', 'path_hash_prefixes', and 'delegations' dict keys
    are optional.

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'snapshot', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' is improperly formatted.
    
    tuf.UnknownRoleError, if 'rolename' does not exist.

  <Side Effects>
    None.
  
  <Returns>
    The roleinfo of 'rolename'.
  """
  
  # Raises tuf.FormatError, tuf.UnknownRoleError, or tuf.InvalidNameError.
  _check_rolename(rolename)
  
  return copy.deepcopy(_roledb_dict[rolename])





def get_role_keyids(rolename):
  """
  <Purpose>
    Return a list of the keyids associated with 'rolename'.
    Keyids are used as identifiers for keys (e.g., rsa key).
    A list of keyids are associated with each rolename.
    Signing a metadata file, such as 'root.json' (Root role),
    involves signing or verifying the file with a list of
    keys identified by keyid.

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'snapshot', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' does not have the correct object format. 

    tuf.UnknownRoleError, if 'rolename' cannot be found in the role database.

    tuf.InvalidNameError, if 'rolename' is incorrectly formatted.

  <Side Effects>
    None.

  <Returns>
    A list of keyids.
  """
  
  # Raises tuf.FormatError, tuf.UnknownRoleError, or tuf.InvalidNameError.
  _check_rolename(rolename)

  roleinfo = _roledb_dict[rolename]
  
  return roleinfo['keyids']





def get_role_threshold(rolename):
  """
  <Purpose>
    Return the threshold value of the role associated with 'rolename'.

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'snapshot', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' does not have the correct object format. 

    tuf.UnknownRoleError, if 'rolename' cannot be found in in the role database.

    tuf.InvalidNameError, if 'rolename' is incorrectly formatted.

  <Side Effects>
    None.

  <Returns>
    A threshold integer value.
  """

  # Raises tuf.FormatError, tuf.UnknownRoleError, or tuf.InvalidNameError.
  _check_rolename(rolename)

  roleinfo = _roledb_dict[rolename]
  
  return roleinfo['threshold']





def get_role_paths(rolename):
  """
  <Purpose>
    Return the paths of the role associated with 'rolename'.

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'snapshot', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' does not have the correct object format.

    tuf.UnknownRoleError, if 'rolename' cannot be found in the role database.

    tuf.InvalidNameError, if 'rolename' is incorrectly formatted.

  <Side Effects>
    None.

  <Returns>
    A list of paths. 
  """

  # Raises tuf.FormatError, tuf.UnknownRoleError, or tuf.InvalidNameError.
  _check_rolename(rolename)

  roleinfo = _roledb_dict[rolename]
  
  # Paths won't exist for non-target roles.
  try:
    return roleinfo['paths']
  except KeyError:
    return dict()



def get_role_changes(rolename):

  # Raises tuf.FormatError, tuf.UnknownRoleError, or tuf.InvalidNameError.
  _check_rolename(rolename)

  if rolename in _unwritten_role_changes.keys():
    return _unwritten_role_changes[rolename]
  else:
    return _generate_role_changes_entry(created=False)



def get_delegated_rolenames(rolename):
  """
  <Purpose>
    Return the delegations of a role.  If 'rolename' is 'a/b/c'
    and the role database contains ['a/b/c/d', 'a/b/c/d/e', 'a/b/c'], 
    return ['a/b/c/d', 'a/b/c/d/e']

  <Arguments>
    rolename:
      An object representing the role's name, conformant to 'ROLENAME_SCHEMA'
      (e.g., 'root', 'snapshot', 'timestamp').

  <Exceptions>
    tuf.FormatError, if 'rolename' does not have the correct object format.

    tuf.UnknownRoleError, if 'rolename' cannot be found in the role database.

    tuf.InvalidNameError, if 'rolename' is incorrectly formatted.

  <Side Effects>
    None.

  <Returns>
    A list of rolenames. Note that the rolenames are *NOT* sorted by order of
    delegation.
  """

  # Raises tuf.FormatError, tuf.UnknownRoleError, or tuf.InvalidNameError.
  _check_rolename(rolename)

  # The list of delegated roles to be returned. 
  delegated_roles = []

  # Ensure that we only care about delegated roles!
  rolename_with_slash = rolename + '/'
  for name in get_rolenames():
    if name.startswith(rolename_with_slash):
      delegated_roles.append(name)
  
  return delegated_roles





def clear_roledb():
  """
  <Purpose>
    Reset the roledb database.

  <Arguments>
    None.

  <Exceptions>
    None.

  <Side Effects>
    None.

  <Returns>
    None.
  """

  _roledb_dict.clear()





def _check_rolename(rolename):
  """
  Raise tuf.FormatError if 'rolename' does not match
  'tuf.formats.ROLENAME_SCHEMA', tuf.UnknownRoleError if 'rolename' is not
  found in the role database, or tuf.InvalidNameError if 'rolename' is
  not formatted correctly.
  """
  
  # Does 'rolename' have the correct object format?
  # This check will ensure 'rolename' has the appropriate number of objects 
  # and object types, and that all dict keys are properly named.
  tuf.formats.ROLENAME_SCHEMA.check_match(rolename)

  # Raises tuf.InvalidNameError.
  _validate_rolename(rolename)
  
  if rolename not in _roledb_dict:
    raise tuf.UnknownRoleError('Role name does not exist: '+rolename)





def _validate_rolename(rolename):
  """
  Raise tuf.InvalidNameError if 'rolename' is not formatted correctly.
  It is assumed 'rolename' has been checked against 'ROLENAME_SCHEMA'
  prior to calling this function.
  """

  if rolename == '':
    raise tuf.InvalidNameError('Rolename must not be an empty string')

  if rolename != rolename.strip():
    raise tuf.InvalidNameError(
             'Invalid rolename. Cannot start or end with whitespace: '+rolename)

  if rolename.startswith('/') or rolename.endswith('/'):
    raise tuf.InvalidNameError(
             'Invalid rolename. Cannot start or end with "/": '+rolename)
