#!/usr/bin/env python26

import os
import sys
import subprocess
from pysphere import *
from optparse import OptionParser
from tempfile import mkstemp
import datetime

class  ESXiClass:
    try:
        def __init__(self,host,login,password):
            self.host = host
            self.login = login
            self.password = password
            self.server = VIServer()
            self.server.connect(self.host,self.login,self.password)
    except:
        raise Exception("Cannot connect to the remote server")
        sys.exit()

    #def getStats(self,net_trans,net_recv,cpu_usage,mem_usage,mem_active,mem_consumed,disk_usage,disk_read,disk_write,storagePath_write,storagePath_read):
    def getStats(self,net_trans,net_recv,cpu_usage,mem_usage,mem_active,mem_consumed):
        data = {}
        net_data = {}
        cpu_data = {}
        memu_data = {}
        hosts = self.server.get_hosts()
        datas = self.server.get_datastores()
        print datas
        print dir(self.server)
        prop = self.server.get_datacenters()
        print prop
        host = [k for k,v in hosts.items() if v == self.host][0]
        pm = self.server.get_performance_manager()
        #for key,value in pm.get_entity_counters(host).items():
        #    print key + ": " + str(value)
        #stats = pm.get_entity_statistic(host, [net_trans,net_recv,cpu_usage,mem_usage,mem_active,mem_consumed,disk_usage,disk_read,disk_write,storagePath_write,storagePath_read,datastore_write,datastore_read])
        stats = pm.get_entity_statistic(host, [net_trans,net_recv,cpu_usage,mem_usage,mem_active,mem_consumed])
        for stat in stats:
            #print stat.description
            #print stat.instance
            #print stat.value
            #print stat.group
            #if stat.instance:
            #print stat
            if "net" in stat.group:
                print "stat.instace: %s" % (stat.instance)
                if "vmnic" not in stat.instance:
                    net_data[stat.group+":"+stat.description.replace(' ','')+":total"] = stat.value
                else:
                    net_data[stat.group+":"+stat.description.replace(' ','')+":"+stat.instance] = stat.value
            if "cpu" in stat.group:
                if not stat.instance:
                    print stat.instance
                else:
                    cpu_data[stat.group+":"+stat.description.replace(' ','')+":"+stat.instance] = stat.value
            if "mem" in stat.group:
                memu_data[stat.group+":"+stat.description.replace(' ','')+":"+stat.instance] = stat.value

            data[stat.group+":"+stat.description+":"+stat.instance] = stat.value
        print data
        #data.sort(key=lambda x: x[0])
        sorted(net_data.items())
        proc = open("/tmp/esxi.log", "a")
        for key,value in net_data.items():
            proc.write("%s : %s \n" % (key,value))
        return (net_data,cpu_data,memu_data)
        #try:
        #    (tempfiled,tempfilepath) = mkstemp()
        #    tempfile = open(tempfilepath, 'wb')
        #except:
        #    print "cannot create temporary file"
        #    tempfile.write("%s        %s \n" % (key,value))
        #tempfile.close()

def sendValues(filepath, zabbixserver = "10.66.59.40", zabbixport = "10051", senderloc = "zabbix_sender"):
    r = os.system("%s --zabbix-server '%s' --port '%s' -i '%s' -vv" % (senderloc,zabbixserver,zabbixport,filepath))
    if r != 0:
        raise ErrorSendingValues, "An error occured sending values to the server"


def main():
    parser = OptionParser(
                          usage = "%prog [ -z <esx server or ip>] [-u <username>] [-p <password>]",
                          version = "%prog $Revision$",
                          prog = "ESXiGrapher",
                          description = """This program connects to the ESXi host and sends stats to Zabbix.
                                        Author: Krishna SHK
                                        Licence: GPLv2
                                        """,
                          )
    parser.add_option(
                      "-z",
                      "--server",
                      action = "store",
                      type = "string",
                      dest = "esxiserver",
                      default = "localhost",
                      help = "Address of your radius server",
                    )
    parser.add_option(
                      "-u",
                      "--username",
                      action = "store",
                      type = "string",
                      dest = "username",
                      default = "user",
                      help = "ESXi user name",
                     )
    parser.add_option(
                      "-p",
                      "--password",
                      action = "store",
                      type = "string",
                      dest = "password",
                      default = "password",
                      help = "Password for the ESXi host",
                     )

    (opts,args) = parser.parse_args()
    netdata = {}
    cpudata = {}
    E = ESXiClass(opts.esxiserver,opts.username,opts.password)
    #E.getStats("net.transmitted","net.received","cpu.usage","mem.usage","mem.active","mem.consumed","disk.usage","disk.read","disk.write","storagePath.write","storagePath.read")
    (netdata,cpudata,memudata) = E.getStats("net.transmitted","net.received","cpu.usage","mem.usage","mem.active","mem.consumed")
    #E.getStats("net.received")
    try:
        (tempfiled, tempfilepath) = mkstemp()
        tempfile = open(tempfilepath , 'wb')
    except:
        parser.error("Error creating temporary file")

    try:
        try:
            for key,value in netdata.items():
                tempfile.write("%s esxi[localhost,%s] %s\n" % (opts.esxiserver,key,value))
                print key, value
            for key,value in cpudata.items():
                tempfile.write("%s esxi[localhost,%s] %s\n" % (opts.esxiserver,key,value))
                print key, value
            for key,value in memudata.items():
                tempfile.write("%s esxi[localhost,%s] %s\n" % (opts.esxiserver,key,value))
                print key, value
            tempfile.close()
        except "bogus":
            parser.error("Error creating the file to send")

        try:
            sendValues(filepath=tempfilepath,zabbixserver="10.66.59.40",zabbixport="10051",senderloc="zabbix_sender")
        except ErrorSendingValues:
            parser.error("An error occurred while sending values to the zabbix server")
    finally:
        try:
            fopen = open(tempfilepath,"r")
            for line in fopen.readlines():
                print line.rstrip("\n")
            fopen.close()
            tempfile.close()
        except:
            pass
        os.remove(tempfilepath)

if __name__ == "__main__":
    main()

