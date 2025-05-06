#!/bin/sh

python3 capability_manager.py -i ../sunquan/syzbot/image/bullseye.img \
    -r ../sunquan/syzbot/image/bullseye.id_rsa -p ../sunquan/syzbot/syzbot-6.3-kdfsan/poc \
    -b ../sunquan/syzbot/syzbot-6.3-kdfsan/linux/arch/x86/boot/bzImage --cmp -n 30
