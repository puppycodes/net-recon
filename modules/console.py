#!/usr/bin/python2

import sys
import os
import glob
import random
import json
import readline
import subprocess

from scapy.all import *
from scapy.utils import *

from datetime import date

class ColorOut:

    def __init__(self, str):
        self.str = str

    def red(self):
        return '\033[1;31m[-]\033[1;m {}'.format(self.str)

    def blue(self):
        return '\033[1;34m[>]\033[1;m {}'.format(self.str)

    def green(self):
        return '\033[1;32m[+]\033[1;m {}'.format(self.str)

class NetReconHelp:

    def __init__(self, cmdstr):

        self.cmdstr = cmdstr
        self.parselen = len(cmdstr.split())

        if self.parselen > 1:
            try:
                runcmd = getattr(self, self.cmdstr.split()[1].strip())
                runcmd()

            except AttributeError, err:

                pass

        else:

            try:
                runcmd = getattr(self, self.cmdstr)
                runcmd()

            except AttributeError, err:

                pass

    def capture(self):

        capture_help = '''
Usage : capture <iface>
E.X.  : capture eth0

About: Capture network packets on a specified interface

    '''

    def show(self):

        show_help = '''
Usage : show <all, hosts, ipv4, protocols, fqdn, fingerprints, ports>
E.X.  : show hosts WINADCOMPUTER1337
        show ipv4 192.168.1.14
        show fingerprints
        show all

About: Use this command to show available session infrastructure data

    '''

        print show_help

    def search(self):

        search_help = '''
----------------------------------------------------------
{} Command Help
----------------------------------------------------------
Usage: search <hosts, ipv4, protocols, fqdn, fingerprints, ports>
E.X. : search hosts WINADCOMPUTER321
       search ipv4 192.168.1.1
       search protocol dhcp
       search fqdn WINADCOMPUTER321.WINAD.LOCAL
       search fingerprint Windows Server 2008

About: Use this command to find saved targets
       and/or recon data using search queries.
       For example, a "search protocol lldp"
       command would search for any hosts
       discovered via LLDP and display the hosts
       information.

    '''.format(self.cmdstr)

        print search_help

    def shell(self):

        shell_help = '''
----------------------------------------------------------
{} Command Help
----------------------------------------------------------
Usage: shell <cmd>
E.X. : shell ls -la
       shell whoami && id

About: Execute local shell command

'''

class NetReconConsole:

    def __init__(self, cmdstr, keys):

        self.cmdstr = cmdstr
        self.keys = keys
        self.parselen = len(self.cmdstr.split())

        if self.parselen > 1:

            try:
                runcmd = getattr(self, self.cmdstr.split()[0])
                runcmd(self.keys)

            except AttributeError, err:

                print ColorOut('NetRecon command not found. (CONSOLE)').red()
                print self.cmdstr.split()[0].strip()

        if self.parselen == 1:

            try:
                runcmd = getattr(self, self.cmdstr)
                runcmd(self.keys)

            except AttributeError, err:

                print ColorOut('NetRecon command not found (CONSOLE-2).').red()
                print self.cmdstr

    def help(self, keys):

        if self.parselen == 2:
            NetReconHelp(self.cmdstr)

        else:
            print '''
===========================================
              NetRecon Commands
===========================================
- help
- show
- search
- capture
- shell
- exit

Type "help <command>" for more help.

===========================================
            '''

    def show(self, keys):

        if self.parselen == 3:

            if self.cmdstr.split()[1] in keys.keys():

                if keys[self.cmdstr.split()[1]] != {}:
                    subkeylist = keys[self.cmdstr.split()[1]].keys()

                    if self.cmdstr.split()[2].upper() in sorted(list(set(subkeylist))):

                        hostname = self.cmdstr.split()[2].strip()
                        hostdata = keys[self.cmdstr.split()[1]][self.cmdstr.split()[2].upper()].keys()

                        print hostname

                        for dataname in hostdata:
                            datavalue = keys[self.cmdstr.split()[1]][self.cmdstr.split()[2].upper()][dataname]

                            if type(datavalue) == 'list':
                                datavalue = ', '.join(datavalue)

                            else:
                                datavalue = datavalue

                            print '{0:20} {1:2} {2:1}'.format(dataname.upper(), '-', datavalue)

                else:
                    print ColorOut('No {} settings available.'.format(self.cmdstr.split()[1])).red()

        elif self.parselen == 2:

            if self.cmdstr.split()[1] in keys:

                if keys[self.cmdstr.split()[1]] != {}:
                    subkeylist = keys[self.cmdstr.split()[1]].keys()

                    print '-' * 50
                    print '{}'.format(self.cmdstr.split()[1].strip().capitalize())
                    print '-' * 50

                    for s in sorted(list(set(subkeylist))):
                        print s

                    print '-' * 50

                else:
                    print ColorOut('No {} settings available.'.format(self.cmdstr[1])).red()

            elif self.cmdstr.split()[1].strip() == 'all':

                hostlist = keys['hosts'].keys()
                hostcount = len(hostlist)

                print 'Showing {} hosts'.format(hostcount)

                for host in sorted(list(set(hostlist))):
                    print host

                domainlist = keys['domains'].keys()
                domcount = len(domainlist)

                print 'Showing {} domains'.format(domcount)

                for domain in sorted(list(set(domainlist))):
                    print domain


            else:
                NetReconHelp('show')

        else:
            print ColorOut('Type "help show" for more help on using the "show" command').blue()

    def sessions(self, keys):

        sessions = saved_sessions()

        for skey in sessions.keys():
            print skey, sessions[skey]

    def shell(self, keys):

        if self.parselen >= 2:
            cmd = ' '.join(self.cmdstr.split()[1:]).rstrip()

            os.system(cmd)

        else:
            NetReconHelp(self.cmdstr)

    def history(self, keys):
        '''Handles the saved NetRecon console
           command-line history'''
        history_exists = history_check()

        if history_exists:

            history_buf = load_history()
            history_buf_len = len(history_buf.split('\n'))

            for i in range(1, history_buf_len):
                print '{0:3} {1:5}'.format(i, history_buf.split('\n')[i-1])

        else:

            create_history()

            history_buf = load_history()
            history_buf_len = len(history_buf.split('\n'))

            for i in range(1, history_buf_len):
                print '{0:3} {1:5}'.format(i, history_buf.split('\n')[i-1])

    def search(self, keys):

        if self.parselen >= 2:
            index = self.cmdstr.split()[1].strip()
            query = self.cmdstr.split()[2].strip()

            if index in keys.keys():
                if query.lower() in keys[index].keys():
                    print "Found! "
                    ikeys = keys[index][query.lower()].keys()

                    for ikey in ikeys:
                        print ikey, keys[index][query.lower()][ikey]

                if query.upper() in keys[index].keys():
                    print "Found!"
                    ikeys = keys[index][query.upper()].keys()

                    for ikey in ikeys:
                        print ikey, keys[index][query.upper()][ikey]

            else:
                for rkey in keys.keys():
                    r_keybuf = keys[rkey].keys()
                    for r_obj in r_keybuf:
                        obj_keybuf = keys[rkey][r_obj].keys()
                        if index.lower() in obj_keybuf:
                            select_obj = keys[rkey][r_obj][index.lower()]
                            if query in [select_obj]:
                                 for k in keys[rkey][r_obj].keys():
                                     print k, keys[rkey][r_obj][k]

    def capture(self, keys):

        if self.parselen == 2:
            interfaces = detect_interfaces()

            if self.cmdstr.split()[1].strip() in interfaces:
                print ColorOut('Starting packet capture on network interface: {}...'.format(self.cmdstr.split()[1].strip())).blue()

                sniff(iface=self.cmdstr.split()[1].strip(), prn=pkt_callback, store=0)

        else:
            NetReconHelp(self.cmdstr.split()[0].strip())

def pkt_callback(pkt):
    pkt.show() # debug statement

def detect_interfaces():

    ipkeys = {}
    id = 1

    available_interfaces = subprocess.Popen("ip -o link show | awk -F': ' '{print $2}'", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    iface_buf = available_interfaces.stdout.read().strip()
    iface_err = available_interfaces.stderr.read().strip()

    iface_buf_list = iface_buf.split('\n')

    return sorted(list(set(iface_buf_list)))

def banner():

    os.system('clear')

    banners = '/opt/net-recon/banners'
    banner_index = glob.glob('{}/*'.format(banners))
    banner_file = random.choice(banner_index)

    with open(banner_file,'r') as banner:
        print banner.read()

def run_netrecon_command(cmd, rkeys, rfile):
    '''Small wrapper function to make command calls to
       the API and console classes'''

    if cmd == 'exit':
        print ColorOut('Thank you for using Net-Recon!').blue()

        sys.exit()


    NetReconConsole(cmd, rkeys)

def history_check():
    '''Function to check if a CLI history
       file for NetRecon exists'''
    filepath = '/opt/net-recon/.net-recon_history/*'
    if len(glob(filepath)) == 0:
        return False

    else:
        return True

def session_check(sfile):
    '''Checks if a session file exists'''
    checkfile = glob.glob(sfile)
    if len(checkfile) == 0:
        print "Console session not found: {}".format(checkfile)
        return False

    else:
        print "Console session found: {}".format(checkfile)
        return True

def saved_sessions():
    '''Returns a list of all currently saved
       session files.'''
    savedkeys = {}
    savecount = 1
    sessions = '{}/sessions/'.format(os.getcwd())
    index = glob('{}*'.format(sessions))

    for i in index:
        savedkeys.update({savecount: i})
        savecount += 1

    return savedkeys

def sessions_path_exists():

    sessions_path = '{}/sessions'.format(os.getcwd())
    index = glob(sessions_path)

    if index != []:
        return True

    return False

def json_writer(jdata,jfile):
    '''Function to write JSON data
       to console session file.'''
    with open(jfile, 'w') as sfile:
        json.dump(jdata, sfile)

def json_loader(jfile):
    '''Loads JSON data from file'''
    with open(jfile, 'r') as jdata:
        rdata = json.load(jdata)
        return rdata

def new_keys():
    '''Creates new JSON key blob for
       console session.'''

    new_net_recon_keys = {'hosts':{}, 'domains':{}, 'protocols':{}, 'routers':{}, 'switches':{}, 'fqdns':{}}

    return new_net_recon_keys

def create_session(rfile):
    '''Creates a new net-recon console session'''
    rkeys = new_keys()
    json_writer(rkeys, rfile)
    print "NetRecon console session created."

def create_history():

    os.system('touch /opt/net-recon/.net-recon_history')

def load_history():

    with open('/opt/net-recon/.net-recon_history', 'r') as historyfile:
        return historyfile.read()

def write_history(cmd):

    with open('/opt/net-recon/.net-recon_history', 'a') as historyfile:
        historyfile.write('{}\n'.format(cmd))

def session_handler(sfile=None):
    '''Handles the current console session. If no session file
       is found, a new one will be made. If the session exists,
       the JSON data from that session file is loaded into memory.'''

    check_sessions_path = sessions_path_exists()

    if not check_sessions_path:
        os.system('mkdir {}'.format('{}/sessions'.format(os.getcwd())))

    console_sessions = saved_sessions()

    if sfile:

        loadkeys = json_loader(sfile)

        return sfile,loadkeys

    else:

        current_session = '{}/sessions/net-recon-{}.nrecon'.format(os.getcwd(),date.today())

        if current_session not in console_sessions.values():
            print "Creating console session: {}".format(current_session)

            create_session('{}'.format(current_session))
            loadkeys = json_loader('{}'.format(current_session))

            return current_session,loadkeys

        else:

            loadkeys = json_loader('{}'.format(current_session))

            return current_session,loadkeys

def switch_session(new_session):
    '''Changes the currently loaded session'''

    print "Changing session: {}".format(new_session)

    sessions = saved_sessions()
    newfile, newkeys = session_handler(sfile=new_session)

    return newfile, newkeys

def net_recon_shell(rfile, rkeys):
    '''The net-recon console command shell
       function.'''
    sessions = saved_sessions()
    prompt = '#net-recon ~> '

    print ''
    print ColorOut('Console session loaded: {}'.format(rfile)).green()
    print ColorOut('Type "help" for a full list of commands.').green()
    print ''

    while True:

        readline.get_line_buffer()
        cmd = raw_input(prompt)

        print ''

        if len(cmd) != 0:

            run_netrecon_command(cmd, rkeys, rfile)
            write_history(cmd)
            json_writer(rkeys, rfile)

        else:

            net_recon_shell(rfile, rkeys)

        print ''
