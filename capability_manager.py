from pwn import *
import argparse
import os
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
log = logging.getLogger("UAF Judge")

parser=argparse.ArgumentParser()

parser.add_argument("-b","--bzImage",dest="bzImage",type=str,required=True,help="bzImage")
parser.add_argument("-i","--image",dest="image",type=str,required=True,help="Syzkaller Image")
parser.add_argument("-p","--poc",dest="poc",type=str,required=True,help="Poc to trigger vulnerability")
parser.add_argument("-r","--rsa",type=str,dest="rsa",required=True,help="id_rsa")
parser.add_argument("-n","--num",type=int,dest="num",required=False,help="num",default=10)
parser.add_argument("-t","--time",dest="time",type=int,required=False,help="time",default=60)
parser.add_argument("--batch",dest="batch",type=int,required=False,help="batch",default=5)
parser.add_argument("--cmp",dest="cmp",action="store_true",help="Enable cmp shift")



args=parser.parse_args()

if (
    os.path.isfile(args.image) 
    and os.path.isfile(args.bzImage)
    and os.path.isfile(args.poc)
    and os.path.isfile(args.rsa)
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

Cmp_addr_list=[]
sum_report=[]
rank=0

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
    report=[]
    share_file=f"/dev/shm/ivshmem{num}"
    global rank
    global sum_report
    global lock
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
    capability=[]
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
        report.append(line)
        if CapabilityStr in line and not find_capability:
            log.info(f"\033[31mVM-{num} Find Capability Report\033[0m")
            find_capability=True
            report=report[-1:]
            capability.append(line)
            start=time.time()
        if Cmp_str in line:
            index1=line.find("0x")
            addr=int(line[index1:],16)
            if addr not in Cmp_addr_list:
                Cmp_addr_list.append(addr)
                log.info(f"\033[31mVM-{num} Find New Cmp Addr {hex(addr)}\033[0m")
        if STOP in line:
            log.info(f"VM-{num} Rebooting")
            break 
        if CapabilityStr in line and line not in capability:
            capability.append(line)
            last_time=time.time()
        if time.time()-last_time>total_time:
            log.info(f"VM-{num} No Capability Report")
            break
        if find_capability and time.time()-start>=180:
            log.info(f"VM-{num} We have get {len(capability)} Capability Report")
            break
    vm.close()
    if find_capability:
        with lock:
            for title in capability:
                if title not in sum_report:
                    sum_report.append(title)
            with open(f"VM-{rank}","w") as f:
                for line in report:
                    f.write(line+"\n")
            rank+=1 
            return
            

thread=[]

is_update=0

kinds=len(sum_report)

batch=args.batch

while 1:
    for j in range(args.num):
        thread.append(threading.Thread(target=get_capability_report,args=(j,)))
        thread[j].start()
    for j in range(args.num):
        thread[j].join()
    is_update=len(sum_report)-kinds
    kinds=len(sum_report)
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

num=len(sum_report)

log.info(f"\033[31mCollect Capability Report {num} kinds\033[0m")

with open("title.txt","w") as f:
    for line in sum_report:
        f.write(line+"\n")







