from pwn import *
import argparse
import os
import subprocess
import threading
import logging
import time
import random
import socket
import mmap
import struct

lock = threading.Lock()

def random_port():
    return random.randint(1024, 65535)

def unused_tcp_port():
    while True:
        port = random_port()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("localhost", port))
                return port
            except OSError:
                continue



logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger("UAF Capability Manager")

parser=argparse.ArgumentParser()

parser.add_argument("-b","--bzImage",dest="bzImage",type=str,required=True,help="bzImage")
parser.add_argument("-i","--image",dest="image",type=str,required=True,help="Syzkaller Image")
parser.add_argument("-p","--poc",dest="poc",type=str,required=True,help="Poc to trigger vulnerability")
parser.add_argument("-r","--rsa",type=str,dest="rsa",required=True,help="id_rsa")
parser.add_argument("-n","--num",type=int,dest="num",required=False,help="num",default=10)
parser.add_argument("-t","--time",dest="time",type=int,required=False,help="time",default=60)
parser.add_argument("--batch",dest="batch",type=int,required=False,help="batch",default=5)
parser.add_argument("--cmp",dest="cmp",action="store_true",help="Enable cmp shift")
parser.add_argument("--workdir",dest="workdir",type=str,required=False,help="workdir",default="workdir")
parser.add_argument("--vmlinux",dest="vmlinux",type=str,required=True,help="Get specific info")



args=parser.parse_args()

if (
    os.path.isfile(args.image) 
    and os.path.isfile(args.bzImage)
    and os.path.isfile(args.poc)
    and os.path.isfile(args.rsa)
    and os.path.isfile(args.vmlinux)
):
    pass
else:
    print("[-] File does not exist")
    exit(1)

if args.num<1:
    print("[-] Unreasonable num")
    exit(0)

qemu_cmd=f'qemu-system-x86_64 \
            -smp 4\
	        -m 4G \
	        -kernel {args.bzImage} \
	        -append "console=ttyS0 root=/dev/sda kasan_multi_shot=1 earlyprintk=serial net.ifnames=0" \
	        -net nic,model=e1000 \
	        -drive file={args.image},format=raw \
            -snapshot \
	        -enable-kvm \
	        -nographic  '

shared_device="-device ivshmem-plain,memdev=ivshmem  "
CapabilityStr="[Primitive]"
STOP="Rebooting in"
Cmp_str="KDFSAN: new cmp addr find"
workdir=os.path.abspath(args.workdir)
vmlinux=os.path.abspath(args.vmlinux)

if not os.path.exists(workdir):
    os.makedirs(workdir)

Cmp_addr_list=[]
capabilitys=[]

seperator = "==============================================================="

def get_total_report(name,vm):
    location=name.split(" ")[-2]
    if location.startswith("0x"):
        pass
    else:
        log.info(f"\033[31mFormat Error {name}\033[0m")
        return
    cmd=["addr2line","-p","-f","-e",vmlinux,"-a",location]
    result = subprocess.run(cmd,capture_output=True,check=True,text=True)
    result=result.stdout.strip()
    filename=os.path.join(workdir,str(hash(name)))
    file=os.path.abspath(filename)
    if os.path.exists(file):
        return
    context=[seperator,name,result]
    while 1:
        try:
            line=vm.recvline(timeout=10)
        except Exception as e:
            log.info("Nothing to Recive!!!")
            break
        line=line.decode().strip()
        if "] " in line:
            index=line.find("] ")
            line=line[index+2:]
        context.append(line)
        if line==seperator:
            break
    with open(file,"w") as f:
        for line in context:
            f.write(line+"\n")
    return
            
    

SHM_SIZE = 1 * 1024 * 1024

def Init_shared_mem(filename:str):
    global Cmp_addr_list
    count=len(Cmp_addr_list)
    with open(filename, "r+b") as fd:
        shm = mmap.mmap(fd.fileno(), SHM_SIZE, mmap.MAP_SHARED, mmap.PROT_WRITE)
        shm[0:8] = struct.pack("Q", count)
        for i, num in enumerate(Cmp_addr_list):
            shm[8 + i*8 : 8 + (i+1)*8] = struct.pack("Q", num)
        #log.info(f"Host VM wrote {count} numbers to shared memory")
        shm.close()

def get_capability_report(num:int):
    share_file=f"/dev/shm/ivshmem{num}"
    global capabilitys
    global lock
    global Cmp_addr_list
    port=unused_tcp_port()
    cmdline=f'-net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:{port}-:22 '
    qemu=qemu_cmd+cmdline
    if args.cmp:
        qemu+=shared_device
        qemu+=f"-object memory-backend-file,id=ivshmem,share=on,mem-path={share_file},size=1048576 "
    vm=process(qemu,shell=True)
    try:
        vm.recvuntil(b"syzkaller login:",timeout=300)
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
        log.error(f"Something wrong as VM-{num} start")
        vm.close()
        return
    vm.sendline(b"root")
    log.info(f"VM-{num} start successfully !!!")
    try:
        os.system(f'scp -P {port} -o "StrictHostKeyChecking no" -i {args.rsa}  {args.poc}  root@localhost:/root')
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")
        log.error(f"Something wrong as VM-{num} ssh connection")
        vm.close()
        return
    log.info("POC upload")
    Init_shared_mem(share_file)
    vm.clean()
    poc=os.path.basename(args.poc)
    cmd=f"./{poc}"
    vm.sendline(cmd.encode())
    find_capability=False
    total_time=args.time
    start=time.time()
    last_time=time.time()
    while True:
        try:
            line=vm.recvline(timeout=10)
        except Exception as e:
            log.info("Nothing to Recive!!!")
            break
        #print(line.decode().strip())
        line=line.decode().strip()
        if "] " in line:
            index=line.find("] ")
            line=line[index+2:]
        #print(line)
        if CapabilityStr in line and not find_capability:
            log.info(f"\033[31mVM-{num} Find Capability Report\033[0m")
            find_capability=True
            if line not in capabilitys:
                capabilitys.append(line)
                get_total_report(line,vm)
        if Cmp_str in line:
            index1=line.find("0x")
            addr=int(line[index1:],16)
            if addr not in Cmp_addr_list:
                Cmp_addr_list.append(addr)
                log.info(f"\033[31mVM-{num} Find New Cmp Addr {hex(addr)}\033[0m")
                get_total_report(line,vm)
        if STOP in line:
            log.info(f"VM-{num} Rebooting")
            break 
        if CapabilityStr in line and line not in capabilitys:
            capabilitys.append(line)
            last_time=time.time()
            get_total_report(line,vm)
        if time.time()-last_time>total_time:
            log.info(f"VM-{num} No Capability Report")
            break
        if find_capability and time.time()-start>=180:
            log.info(f"VM-{num} Close")
            break
    vm.close()
            

thread=[]

is_update=0

kinds=len(capabilitys)

batch=args.batch

while 1:
    for j in range(args.num):
        thread.append(threading.Thread(target=get_capability_report,args=(j,)))
        thread[j].start()
    for j in range(args.num):
        thread[j].join()
    is_update=len(capabilitys)-kinds
    kinds=len(capabilitys)
    log.info(f"\033[31mUpdate {is_update} Capability Report\033[0m")  
    if not is_update:
        batch+=1
        if batch>=args.batch:
            log.info("Collection Stop")
            break
    else:
        batch=0
    is_update=0
    thread.clear()

num=len(capabilitys)

log.info(f"\033[31mCollect Capability Report {num} kinds\033[0m")







