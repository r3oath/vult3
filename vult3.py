# ----------------------------------------------------------------------------
# ////////////////////////////////////////////////////////////////////////////
#
# Vult3 - Windows API Middle-Man Process Monitor.
#   Copyright (C) 2013 Tristan Strathearn.
#   Email: r3oath@gmail.com
#   Website: www.r3oath.com
#
# ////////////////////////////////////////////////////////////////////////////
# ----------------------------------------------------------------------------

import sys
import argparse
import datetime

try:
    import prettytable
except:
    print 'You need to have PrettyTable installed.'
    print 'https://pypi.python.org/pypi/PrettyTable'
    sys.exit()

try:
    from pydbg import *
    from pydbg.defines import *
    import hooking
except:
    print 'You need to have PyDbg installed.'
    print 'https://github.com/OpenRCE/pydbg'
    print 'Get the unofficial binaries at:'
    print 'http://www.lfd.uci.edu/~gohlke/pythonlibs/#pydbg'
    sys.exit()

# ----------------------------------------------------------------------------

BANNER = r"""
     _          _   _                  _           _           _
    /\ \    _ / /\ /\_\               _\ \        /\ \       /\ \
    \ \ \  /_/ / // / /         _    /\__ \       \_\ \     /  \ \
     \ \ \ \___\/ \ \ \__      /\_\ / /_ \_\      /\__ \   / /\ \ \
     / / /  \ \ \  \ \___\    / / // / /\/_/     / /_ \ \ / / /\ \ \
     \ \ \   \_\ \  \__  /   / / // / /         / / /\ \ \\/_//_\ \ \
      \ \ \  / / /  / / /   / / // / /         / / /  \/_/  __\___ \ \
       \ \ \/ / /  / / /   / / // / / ____    / / /        / /\   \ \ \
        \ \ \/ /  / / /___/ / // /_/_/ ___/\ / / /        / /_/____\ \ \
         \ \  /  / / /____\/ //_______/\__\//_/ /        /__________\ \ \
          \_\/   \/_________/ \_______\/    \_\/         \_____________\/

                    Vult3 - Windows API Man-in-the-middle.
                Created by Tristan Strathearn (www.r3oath.com)
"""

HOOKS = None

# ----------------------------------------------------------------------------
# ////////////////////////////////////////////////////////////////////////////
#
# HOOKS DB:
#   Defines function hooks for various system DLL's that interact with the
#   file system, registry, network etc. Feel free to extend these or add
#   your own. The format should be fairy easy to follow. The actual loading
#   and triggering of the hooks is taken care of by Vult3.
#
# ////////////////////////////////////////////////////////////////////////////
# ----------------------------------------------------------------------------

def fhook_msvcr110_strcpy(dbg_inst, args):
    _fhelper_function_name('fhook_msvcr110_strcpy')
    # Get the destination string (if it exists).
    buf_size = _fhelper_calc_nb_ending(dbg_inst, dbg_inst.get_arg(1))
    dest = dbg_inst.read_process_memory(dbg_inst.get_arg(1), buf_size)
    dest_string = dbg_inst.get_printable_string(dest, True)
    LOGGER.pass_('Destination String -> %s' % dest_string, only_log=True)
    # Get the source string.
    buf_size = _fhelper_calc_nb_ending(dbg_inst, dbg_inst.get_arg(2))
    src = dbg_inst.read_process_memory(dbg_inst.get_arg(2), buf_size)
    src_string = dbg_inst.get_printable_string(src, True)
    LOGGER.pass_('Source String -> %s' % src_string, only_log=True)
    return _fhelper_dbg_continue()

def fhook_msvcr110_strcpy_s(dbg_inst, args):
    _fhelper_function_name('fhook_msvcr110_strcpy_s')
    # Get the destination string (if it exists).
    buf_size = _fhelper_calc_nb_ending(dbg_inst, dbg_inst.get_arg(1))
    dest = dbg_inst.read_process_memory(dbg_inst.get_arg(1), buf_size)
    dest_string = dbg_inst.get_printable_string(dest, True)
    LOGGER.pass_('Destination String -> %s' % dest_string, only_log=True)
    LOGGER.pass_('Destination Size -> %i' %
                 int(dbg_inst.get_arg(2)), only_log=True)
    # Get the source string.
    buf_size = _fhelper_calc_nb_ending(dbg_inst, dbg_inst.get_arg(3))
    src = dbg_inst.read_process_memory(dbg_inst.get_arg(3), buf_size)
    src_string = dbg_inst.get_printable_string(src, True)
    LOGGER.pass_('Source String -> %s' % src_string, only_log=True)
    return _fhelper_dbg_continue()

def fhook_kernel32_WriteFile(dbg_inst, args):
    _fhelper_function_name('fhook_kernel32_WriteFile')
    explored = dbg_inst.read_process_memory(dbg_inst.get_arg(2),
                                            int(dbg_inst.get_arg(3)))
    explored_string = dbg_inst.get_printable_string(explored, True)
    LOGGER.pass_('Buffer Dump -> %s' % explored_string, only_log=True)
    return _fhelper_dbg_continue()

def fhook_kernel32_WriteFileEx(dbg_inst, args):
    _fhelper_function_name('fhook_kernel32_WriteFileEx')
    explored = dbg_inst.read_process_memory(dbg_inst.get_arg(2),
                                            int(dbg_inst.get_arg(3)))
    explored_string = dbg_inst.get_printable_string(explored, True)
    LOGGER.pass_('Buffer Dump -> %s' % explored_string, only_log=True)
    return _fhelper_dbg_continue()

def fhook_kernel32_WriteProcessMemory(dbg_inst, args):
    return _fhelper_context_dump(fname='fhook_kernel32_WriteProcessMemory',
                                 dbg_inst=dbg_inst)

def fhook_advapi32_RegCreateKeyEx(dbg_inst, args):
    _fhelper_function_name('fhook_advapi32_RegCreateKeyEx')
    # Get the HKEY
    hkey_code = _fhelper_get_hkey_token(dbg_inst.get_arg(1))
    LOGGER.pass_('HKEY -> %s' % hkey_code, only_log=True)
    # Get the Subkey
    buf_size = _fhelper_calc_nb_ending(dbg_inst, dbg_inst.get_arg(2))
    explored = dbg_inst.read_process_memory(dbg_inst.get_arg(2), buf_size)
    explored_string = dbg_inst.get_printable_string(explored, True)
    LOGGER.pass_('Subkey -> %s' % explored_string, only_log=True)
    return _fhelper_dbg_continue()

def fhook_advapi32_RegCreateKeyExW(dbg_inst, args):
    _fhelper_function_name('fhook_advapi32_RegCreateKeyExW')
    # Get the HKEY
    hkey_code = _fhelper_get_hkey_token(dbg_inst.get_arg(1))
    LOGGER.pass_('HKEY -> %s' % hkey_code, only_log=True)
    # Get the Subkey
    buf_size = _fhelper_calc_2nb_ending(dbg_inst, dbg_inst.get_arg(2))
    explored = dbg_inst.read_process_memory(dbg_inst.get_arg(2), buf_size)
    explored_string = dbg_inst.get_printable_string(explored, True)
    LOGGER.pass_('Subkey -> %s' % _fhelper_strip_dots(explored_string),
                 only_log=True)
    return _fhelper_dbg_continue()

def fhook_advapi32_RegDeleteKeyEx(dbg_inst, args):
    return _fhelper_context_dump(fname='fhook_advapi32_RegDeleteKeyEx',
                                 dbg_inst=dbg_inst)

def fhook_advapi32_RegDeleteKeyExW(dbg_inst, args):
    return _fhelper_context_dump(fname='fhook_advapi32_RegDeleteKeyExW',
                                 dbg_inst=dbg_inst)

def fhook_advapi32_RegGetValue(dbg_inst, args):
    return _fhelper_context_dump(fname='fhook_advapi32_RegGetValue',
                                 dbg_inst=dbg_inst)

def fhook_advapi32_RegLoadKey(dbg_inst, args):
    return _fhelper_context_dump(fname='fhook_advapi32_RegLoadKey',
                                 dbg_inst=dbg_inst)

def fhook_advapi32_RegOpenKeyEx(dbg_inst, args):
    _fhelper_function_name('fhook_advapi32_RegOpenKeyEx')
    # Get the HKEY
    hkey_code = _fhelper_get_hkey_token(dbg_inst.get_arg(1))
    LOGGER.pass_('HKEY -> %s' % hkey_code, only_log=True)
    # Get the Subkey
    buf_size = _fhelper_calc_nb_ending(dbg_inst, dbg_inst.get_arg(2))
    explored = dbg_inst.read_process_memory(dbg_inst.get_arg(2), buf_size)
    explored_string = dbg_inst.get_printable_string(explored, True)
    LOGGER.pass_('Subkey -> %s' % explored_string, only_log=True)
    return _fhelper_dbg_continue()

def fhook_advapi32_RegOpenKeyExW(dbg_inst, args):
    _fhelper_function_name('fhook_advapi32_RegOpenKeyExW')
    # Get the HKEY
    hkey_code = _fhelper_get_hkey_token(dbg_inst.get_arg(1))
    LOGGER.pass_('HKEY -> %s' % hkey_code, only_log=True)
    # Get the Subkey
    buf_size = _fhelper_calc_2nb_ending(dbg_inst, dbg_inst.get_arg(2))
    explored = dbg_inst.read_process_memory(dbg_inst.get_arg(2), buf_size)
    explored_string = dbg_inst.get_printable_string(explored, True)
    LOGGER.pass_('Subkey -> %s' % _fhelper_strip_dots(explored_string),
                 only_log=True)
    return _fhelper_dbg_continue()

def fhook_advapi32_RegReplaceKey(dbg_inst, args):
    return _fhelper_context_dump(fname='fhook_advapi32_RegReplaceKey',
                                 dbg_inst=dbg_inst)

def fhook_advapi32_RegSetValueEx(dbg_inst, args):
    _fhelper_function_name('fhook_advapi32_RegSetValueEx')
    # Get the name of the value
    buf_size = _fhelper_calc_nb_ending(dbg_inst, dbg_inst.get_arg(2))
    explored = dbg_inst.read_process_memory(dbg_inst.get_arg(2), buf_size)
    explored_string = dbg_inst.get_printable_string(explored, True)
    LOGGER.pass_('Value Name -> %s' % explored_string, only_log=True)
    # Get the value contents
    explored = dbg_inst.read_process_memory(dbg_inst.get_arg(5),
                                            int(dbg_inst.get_arg(6)))
    explored_string = dbg_inst.hex_dump(explored)
    LOGGER.pass_('Buffer Dump -> %s' % explored_string, only_log=True)
    return _fhelper_dbg_continue()

def fhook_advapi32_RegSetValueExW(dbg_inst, args):
    _fhelper_function_name('fhook_advapi32_RegSetValueExW')
    # Get the name of the value
    buf_size = _fhelper_calc_2nb_ending(dbg_inst, dbg_inst.get_arg(2))
    explored = dbg_inst.read_process_memory(dbg_inst.get_arg(2), buf_size)
    explored_string = dbg_inst.get_printable_string(explored, True)
    LOGGER.pass_('Value Name -> %s' % _fhelper_strip_dots(explored_string),
                 only_log=True)
    # Get the value contents
    # Multiplying the buffer length by 2 to take into account the null byte
    # between each buffer byte if type is REG_SZ.
    buf_size = int(dbg_inst.get_arg(6))
    if dbg_inst.get_arg(4) == 1: # REG_SZ = 1
        buf_size = buf_size * 2
    explored = dbg_inst.read_process_memory(dbg_inst.get_arg(5), buf_size)
    explored_string = dbg_inst.hex_dump(explored)
    LOGGER.pass_('Buffer Dump -> %s' % explored_string, only_log=True)
    return _fhelper_dbg_continue()

def fhook_advapi32_RegSetKeyValue(dbg_inst, args):
    return _fhelper_context_dump(fname='fhook_advapi32_RegSetKeyValue',
                                 dbg_inst=dbg_inst)

def fhook_ws2_32_socket(dbg_inst, args):
    _fhelper_function_name('fhook_ws2_32_socket')
    # Get the address family
    family = dbg_inst.get_arg(1)
    if family == 23: family = 'AF_INET6 (IPv6)'
    elif family == 2: family = 'AF_INET (IPv4)'
    else: family = str(family)
    # Get the protocol
    protocol = dbg_inst.get_arg(3)
    if protocol == 6: protocol = 'IPPROTO_TCP'
    elif protocol == 17: protocol = 'IPPROTO_UDP'
    elif protocol == 0: protocol = 'IPPROTO_IP'
    else: family = str(family)
    # Log.
    LOGGER.pass_('Address Family -> %s' % family, only_log=True)
    LOGGER.pass_('Protocol -> %s' % protocol, only_log=True)
    return _fhelper_dbg_continue()

def fhook_ws2_32_bind(dbg_inst, args):
    _fhelper_function_name('fhook_ws2_32_bind')
    addr = dbg_inst.get_arg(2)
    addr_len = dbg_inst.get_arg(3)
    if addr_len == 16: addr = _fhelper_ipv4_itos(addr)
    else: addr = str(addr)
    LOGGER.pass_('Bind Address -> %s' % addr, only_log=True)
    # print dbg_inst.pid_to_port(dbg_inst.pid)
    return _fhelper_dbg_continue()

def fhook_ws2_32_connect(dbg_inst, args):
    _fhelper_function_name('fhook_ws2_32_connect')
    addr = dbg_inst.get_arg(2)
    addr_len = dbg_inst.get_arg(3)
    if addr_len == 16: addr = _fhelper_ipv4_itos(addr)
    else: addr = str(addr)
    LOGGER.pass_('Bind Address -> %s' % addr, only_log=True)
    return _fhelper_dbg_continue()

def fhook_ws2_32_listen(dbg_inst, args):
    return _fhelper_context_dump(fname='fhook_ws2_32_listen',
                                 dbg_inst=dbg_inst)

def fhook_ws2_32_recv(dbg_inst, args):
    return _fhelper_context_dump(fname='fhook_ws2_32_recv',
                                 dbg_inst=dbg_inst)

def fhook_ws2_32_recvfrom(dbg_inst, args):
    return _fhelper_context_dump(fname='fhook_ws2_32_recvfrom',
                                 dbg_inst=dbg_inst)

def fhook_ws2_32_send(dbg_inst, args):
    return _fhelper_context_dump(fname='fhook_ws2_32_send',
                                 dbg_inst=dbg_inst)

def fhook_ws2_32_sendto(dbg_inst, args):
    return _fhelper_context_dump(fname='fhook_ws2_32_sendto',
                                 dbg_inst=dbg_inst)

def fhook_ws2_32_accept(dbg_inst, args):
    return _fhelper_context_dump(fname='fhook_ws2_32_accept',
                                 dbg_inst=dbg_inst)

def fhook_ws2_32_TransmitFile(dbg_inst, args):
    return _fhelper_context_dump(fname='fhook_ws2_32_TransmitFile',
                                 dbg_inst=dbg_inst)

def fhook_ws2_32_TransmitPackets(dbg_inst, args):
    return _fhelper_context_dump(fname='fhook_ws2_32_TransmitPackets',
                                 dbg_inst=dbg_inst)

def _fhelper_function_name(fname):
    LOGGER.touch('', only_log=True)
    LOGGER.touch('/' * 78, only_log=True)
    fname = fname.replace('fhook_', '')
    fname = fname.replace('_', '.')
    LOGGER.touch('Hook Triggered -> %s' % fname)

def _fhelper_context_dump(fname=None, dbg_inst=None):
    if fname != None:
        _fhelper_function_name(fname)
    if dbg_inst != None:
        LOGGER.pass_(dbg_inst.dump_context(context=dbg_inst.context,
                     stack_depth=5), only_log=True)
    return _fhelper_dbg_continue()

def _fhelper_dbg_continue():
    LOGGER.touch('', only_log=True)
    return DBG_CONTINUE

def _fhelper_calc_2nb_ending(dbg_inst, address, max_search=2048):
    old_address = address
    length = 0
    while True:
        byte1 = dbg_inst.read_process_memory(address, 1)
        length = address - old_address
        if ord(byte1) == 0:
            byte2 = dbg_inst.read_process_memory((address + 1), 1)
            if ord(byte2) == 0:
                # We've hit the 2NB's!
                return length
        if length >= max_search:
            return 0
        address = address + 1

def _fhelper_calc_nb_ending(dbg_inst, address, max_search=2048):
    old_address = address
    length = 0
    while True:
        byte1 = dbg_inst.read_process_memory(address, 1)
        length = address - old_address
        if ord(byte1) == 0:
            return length
        if length >= max_search:
            return 0
        address = address + 1

def _fhelper_strip_dots(dump):
    return dump.replace('.', '')

def _fhelper_get_hkey_token(hkey):
    if hkey == 2147483649: return 'HKEY_CURRENT_USER'
    elif hkey == 2147483650: return 'HKEY_LOCAL_MACHINE'
    elif hkey == 2147483648: return 'HKEY_CLASSES_ROOT'
    else: return str(hkey)

def _fhelper_ipv4_itos(ip):
    return '.'.join(map(lambda n: str(ip >> n & 0xFF), [24, 16, 8, 0]))

# ----------------------------------------------------------------------------
# ////////////////////////////////////////////////////////////////////////////
#
# The following is the table relating the function handlers to the specific
# DLL's. This DB is used by the Vult3 SPY whenever a process loads
# a DLL into memory.
#
# ////////////////////////////////////////////////////////////////////////////
# ----------------------------------------------------------------------------

HOOKS_DB = {
    'msvcr110.dll': [
        {
            'function': 'strcpy', # EXTENDED
            'handler': fhook_msvcr110_strcpy,
            'verbose': False
        },
        {
            'function': 'strcpy_s', # EXTENDED
            'handler': fhook_msvcr110_strcpy_s,
            'verbose': False
        }],
    'kernel32.dll': [
        {
            'function': 'WriteFile', # EXTENDED
            'handler': fhook_kernel32_WriteFile,
            'verbose': False
        },
        {
            'function': 'WriteFileEx', # EXTENDED
            'handler': fhook_kernel32_WriteFileEx,
            'verbose': False
        },
        {
            'function': 'WriteProcessMemory',
            'handler': fhook_kernel32_WriteProcessMemory,
            'verbose': False
        }],
    'ws2_32.dll': [
        {
            'function': 'socket', # EXTENDED
            'handler': fhook_ws2_32_socket,
            'verbose': False
        },
        {
            'function': 'bind', # EXTENDED
            'handler': fhook_ws2_32_bind,
            'verbose': False
        },
        {
            'function': 'connect', # EXTENDED
            'handler': fhook_ws2_32_connect,
            'verbose': False
        },
        {
            'function': 'listen',
            'handler': fhook_ws2_32_listen,
            'verbose': False
        },
        {
            'function': 'recv',
            'handler': fhook_ws2_32_recv,
            'verbose': True
        },
        {
            'function': 'recvfrom',
            'handler': fhook_ws2_32_recvfrom,
            'verbose': True
        },
        {
            'function': 'send',
            'handler': fhook_ws2_32_send,
            'verbose': True
        },
        {
            'function': 'sendto',
            'handler': fhook_ws2_32_sendto,
            'verbose': True
        },
        {
            'function': 'accept',
            'handler': fhook_ws2_32_accept,
            'verbose': False
        },
        {
            'function': 'TransmitFile',
            'handler': fhook_ws2_32_TransmitFile,
            'verbose': True
        },
        {
            'function': 'TransmitPackets',
            'handler': fhook_ws2_32_TransmitPackets,
            'verbose': True
        }],
    'advapi32.dll': [
        {
            'function': 'RegCreateKeyEx', # EXTENDED
            'handler': fhook_advapi32_RegCreateKeyEx,
            'verbose': False
        },
        {
            'function': 'RegCreateKeyExW', # EXTENDED
            'handler': fhook_advapi32_RegCreateKeyExW,
            'verbose': False
        },
        {
            'function': 'RegDeleteKeyEx',
            'handler': fhook_advapi32_RegDeleteKeyEx,
            'verbose': False
        },
        {
            'function': 'RegDeleteKeyExW',
            'handler': fhook_advapi32_RegDeleteKeyExW,
            'verbose': False
        },
        {
            'function': 'RegGetValue',
            'handler': fhook_advapi32_RegGetValue,
            'verbose': False
        },
        {
            'function': 'RegLoadKey',
            'handler': fhook_advapi32_RegLoadKey,
            'verbose': False
        },
        {
            'function': 'RegOpenKeyEx', # EXTENDED
            'handler': fhook_advapi32_RegOpenKeyEx,
            'verbose': False
        },
        {
            'function': 'RegOpenKeyExW', # EXTENDED
            'handler': fhook_advapi32_RegOpenKeyExW,
            'verbose': False
        },
        {
            'function': 'RegReplaceKey',
            'handler': fhook_advapi32_RegReplaceKey,
            'verbose': False
        },
        {
            'function': 'RegSetValueEx', # EXTENDED
            'handler': fhook_advapi32_RegSetValueEx,
            'verbose': False
        },
        {
            'function': 'RegSetValueExW', # EXTENDED
            'handler': fhook_advapi32_RegSetValueExW,
            'verbose': False
        },
        {
            'function': 'RegSetKeyValue',
            'handler': fhook_advapi32_RegSetKeyValue,
            'verbose': False
        }]
}

# ----------------------------------------------------------------------------
# ////////////////////////////////////////////////////////////////////////////
#
# END OF EDITABLE SECTION.
#   Everything below is Vult3 core code, and should not be edited if your
#   only purpose was modifying or extending the HOOKS DB.
#
# ////////////////////////////////////////////////////////////////////////////
# ----------------------------------------------------------------------------

class r3spy():
    """The engine of Vult3"""
    def __init__(self, hooks_db):
        """Initialize

        Keyword Arguments:
        hooks_db -- Reference to the HOOKS DB.

        """
        self.dbg = pydbg()
        self.dbg.get_debug_privileges()
        self.FUNCTION_HOOKS = hooks_db
        self.verbose = False

    def addHooksContainer(self, container):
        """Add a Reference to the hooks container.

        Keyword Arguments:
        container -- The hooks container.

        """
        self.hooks = container

    def addLogger(self, logger):
        """Add a Reference to the logger.

        Keyword Arguments:
        logger -- The logger.

        """
        self.logger = logger

    def setVerboseHooks(self):
        self.verbose = True

    def getProcesses(self):
        """Get a list of running processes and PID's."""
        return self.dbg.enumerate_processes()

    def attach(self, pid):
        """Attach to a process via its PID."""
        self.dbg.attach(pid)
        self.dbg.debug_set_process_kill_on_exit(True)

    def load(self, process):
        """Load a process by path/name."""
        self.dbg.load(process)
        self.dbg.debug_set_process_kill_on_exit(True)

    def run(self):
        """Start the process."""
        self.dbg.run()

    def setCallback(self, event, handler):
        """Register an EVENT callback.

        Keyword Arguments:
        event -- The EVENT definition.
        handler -- Function to handle the event.

        """
        self.dbg.set_callback(event, handler)

    def dllLoadHandler(self, dbg_inst):
        """Handle each DLL as it's loaded by the running process.

        Keyword Arguments:
        dbg_inst -- DBG instance passed in by pydbg.

        """
        DLL = dbg_inst.get_system_dll(-1).name.lower()
        self.logger.touch('DLL Loaded -> %s' % DLL, only_log=True)

        if DLL in self.FUNCTION_HOOKS:
            for hook in self.FUNCTION_HOOKS[DLL]:
                if self.verbose == False and hook['verbose'] == True:
                    continue
                try:
                    addr = dbg_inst.func_resolve(DLL,
                                                 hook['function'])
                    self.hooks.add(dbg_inst, addr, 2, hook['handler'])
                    self.logger.touch('Hook registered -> %s => %s' %
                                     (DLL, hook['function']))
                except:
                    pass

        return DBG_CONTINUE

SPY = r3spy(HOOKS_DB)

# ----------------------------------------------------------------------------

class r3logger():
    """Logs console output to file for later inspection."""
    def __init__(self):
        """Initialize."""
        self.log_file = ('output-%s.log' %
            datetime.datetime.now().strftime('%d-%m-%y-%H-%M-%S'))
        try:
            fd = open(self.log_file, 'w')
            fd.write('Generated by Vult3 (www.r3oath.com)\n\n')
            fd.close()
        except:
            pass

    def touch(self, text, only_log=False):
        """Print the text to the console window using the print_ method
        and save the output to file.

        Keyword Arguments:
        text -- The text to print/log.
        only_log -- Whether to only log the text. (Defualt False)

        """
        try:
            fd = open(self.log_file, 'a')
            fd.write(text + '\n')
            fd.close()
        except:
            pass
        if only_log == False: print_(text)

    def pass_(self, text, only_log=False):
        """Same as touch, except don't use the print_ method.

        Keyword Arguments:
        text -- The text to print/log.
        only_log -- Whether to only log the text. (Defualt False)

        """
        try:
            fd = open(self.log_file, 'a')
            fd.write(text + '\n')
            fd.close()
        except:
            pass
        if only_log == False: print text

    def getFile(self):
        """Get the name of the current log file."""
        return self.log_file

LOGGER = r3logger()

# ----------------------------------------------------------------------------

def userInput(text, default_answer=''):
    """Grab input from the user and offer the choice of a defualt answer.

    Keyword Arguments:
    text -- The text to display to the user.
    default_answer -- The default answer to use if no input is given.

    """
    input_ = ''
    if len(default_answer) != 0:
        input_ = raw_input('%s [%s]: ' % (text, default_answer))
    else:
        input_ = raw_input('%s: ' % text)
        if len(input_) == 0:
            return userInput(text)
    if len(input_) == 0:
        input_ = default_answer
    return input_

def print_(text, hl=False):
    """Print a line of text to the screen.

    Keyword Arguments:
    text -- The text to print.
    hl -- Whether to highlight the line. (Defualt False).

    """
    line = text
    if hl == True: print '/' * len(line)
    print line
    if hl == True: print '/' * len(line)

def newLine():
    """Creates a new line, for spacing out printed text etc."""
    print ''

def showProcesses(processes):
    """Show a table of all running processes.

    Keyword Arguments:
    processes -- The list of running processes to print.

    """
    process_names   = []
    process_pids    = []

    for pid, name in processes:
        process_names.append(name)
        process_pids.append(pid)

    pt = prettytable.PrettyTable()
    pt.add_column('Process Name', process_names, align='l')
    pt.add_column('PID', process_pids, align='r')
    print pt
    newLine()

# ----------------------------------------------------------------------------

def main(args):
    print BANNER

    processes = userInput('View running processes? (Y)es or (N)o',
                          'Y').lower()
    if processes == 'y':
        showProcesses(SPY.getProcesses())

    while True:
        action = userInput('Would you like to (A)ttach or (L)oad a process?',
                           'A').lower()

        if action == 'a':
            pid = userInput('PID of process to attach too')
            try:
                SPY.attach(int(pid))
                LOGGER.touch('Attached to PID: %d' % int(pid))
                break
            except:
                print_('Could not attach to process with PID: %s' % pid,
                       hl=True)
                sys.exit()
        elif action == 'l':
            program = userInput('Process to load')
            try:
                SPY.load(program)
                LOGGER.touch('Loaded process: %s' % program)
                break
            except:
                print_('Could not load: %s' % program, hl=True)
                sys.exit()
        else:
            print_('Please respond with either A or L.')

    verbose = userInput('Register extended function hooks? (Y)es or (N)o',
                        'N')
    if verbose.lower() == 'y':
        SPY.setVerboseHooks()

    newLine()

    # Prepare our function hooks.
    HOOKS = hooking.hook_container()
    SPY.addLogger(LOGGER)
    SPY.addHooksContainer(HOOKS)
    SPY.setCallback(LOAD_DLL_DEBUG_EVENT, SPY.dllLoadHandler)

    # Let the application run free ;)
    SPY.run()
    print_('Finished! Check the log for details -> %s' % LOGGER.getFile(),
           hl=True)

if __name__ == "__main__":
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        newLine()
        print_('User cancelled process, ending Vult3.')
