#!/usr/bin/python3
# Copyright (c) Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")

from operator import mod
import os
import subprocess
from bcc import SymbolCache, BPF
from unittest import main, TestCase
from utils import mayFail

class TestKSyms(TestCase):
    def grab_sym(self):
        address = ""
        aliases = []

        # Grab the first symbol in kallsyms that has type 't' or 'T'.
        # Also, find all aliases of this symbol which are identifiable
        # by the same address.
        with open("/proc/kallsyms", "rb") as f:
            for line in f:

                # Extract the first 3 columns only. The 4th column
                # containing the module name may not exist for all
                # symbols.
                (addr, t, name) = line.strip().split()[:3]
                if t == b"t" or t == b"T":
                    if not address:
                        address = addr
                    if addr == address:
                        aliases.append(name)

        # Return all aliases of the first symbol.
        return (address, aliases)

    def test_ksymname(self):
        sym = BPF.ksymname(b"__kmalloc")
        self.assertIsNotNone(sym)
        self.assertNotEqual(sym, 0)

    def test_ksym(self):
        (addr, aliases) = self.grab_sym()
        sym = BPF.ksym(int(addr, 16))
        found = sym in aliases
        self.assertTrue(found)

# c/c++ 测试
class HarnessCPP(TestCase):
    def setUp(self):
        self.build_command()
        subprocess.check_output('objcopy --only-keep-debug cc_dummy cc_dummy.debug'
                                .split())
        self.debug_command()
        subprocess.check_output('strip cc_dummy'.split())
        self.process = subprocess.Popen('./cc_dummy', stdout=subprocess.PIPE)
        # The process prints out the address of some symbol, which we then
        # try to resolve in the test.
        self.addr = int(self.process.stdout.readline().strip(), 16)
        self.syms = SymbolCache(self.process.pid)

    def tearDown(self):
        self.process.kill()
        self.process.wait()
        self.process.stdout.close()
        self.process = None

    # 解析地址=>函数符号
    def resolve_addr(self):
        sym, offset, module = self.syms.resolve(self.addr, False)
        self.assertEqual(offset, 0)
        self.assertTrue(module[-8:] == b'cc_dummy')
        sym, offset, module = self.syms.resolve(self.addr, True)
        self.assertEqual(sym, b'some_namespace::some_function(int, int)')
        self.assertEqual(offset, 0)
        self.assertTrue(module[-8:] == b'cc_dummy')

    # 解析函数符号=>地址
    def resolve_name(self):
        script_dir = os.path.dirname(os.path.realpath(__file__).encode("utf8"))
        addr = self.syms.resolve_name(os.path.join(script_dir, b'cc_dummy'),
                                      self.mangled_name)
        self.assertEqual(addr, self.addr)
        pass

class TestDebuglinkCPP(HarnessCPP):
    def build_command(self):
        subprocess.check_output('g++ -o cc_dummy cc_dummy.cc'.split())
        lines = subprocess.check_output('nm cc_dummy'.split()).splitlines()
        for line in lines:
            if b"some_function" in line:
                self.mangled_name = line.split(b' ')[2]
                break
        self.assertTrue(self.mangled_name)

    def debug_command(self):
        subprocess.check_output('objcopy --add-gnu-debuglink=cc_dummy.debug cc_dummy'
                                .split())
        

    def tearDown(self):
        super(TestDebuglinkCPP, self).tearDown()
        subprocess.check_output('rm cc_dummy cc_dummy.debug'.split())

    def test_resolve_addr(self):
        self.resolve_addr()

    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_resolve_name(self):
    #     self.resolve_name()

class TestBuildidCPP(HarnessCPP):
    def build_command(self):
        subprocess.check_output(('g++ -o cc_dummy -Xlinker ' + \
               '--build-id=0x123456789abcdef0123456789abcdef012345678 cc_dummy.cc')
               .split())
        lines = subprocess.check_output('nm cc_dummy'.split()).splitlines()
        for line in lines:
            if b"some_function" in line:
                self.mangled_name = line.split(b' ')[2]
                break
        self.assertTrue(self.mangled_name)


    def debug_command(self):
        subprocess.check_output('mkdir -p /usr/lib/debug/.build-id/12'.split())
        subprocess.check_output(('mv cc_dummy.debug /usr/lib/debug/.build-id' + \
            '/12/3456789abcdef0123456789abcdef012345678.debug').split())

    def tearDown(self):
        super(TestBuildidCPP, self).tearDown()
        subprocess.check_output('rm cc_dummy'.split())
        subprocess.check_output(('rm /usr/lib/debug/.build-id/12' +
            '/3456789abcdef0123456789abcdef012345678.debug').split())

    def test_resolve_name(self):
        self.resolve_addr()

    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_resolve_addr(self):
    #     self.resolve_name()

# go测试
class HarnessGo(TestCase):
    def setUp(self):
        self.build_command()
        subprocess.check_output('objcopy --only-keep-debug go_dummy go_dummy.debug'.split())
        self.debug_command()
        subprocess.check_output('strip go_dummy'.split())
        self.process = subprocess.Popen('./go_dummy', stdout=subprocess.PIPE)
        # The process prints out the address of some symbol, which we then
        # try to resolve in the test.
        self.addr = int(self.process.stdout.readline().strip(), 16)
        self.syms = SymbolCache(self.process.pid)

    def tearDown(self):
        self.process.kill()
        self.process.wait()
        self.process.stdout.close()
        self.process = None

    # 解析地址=>函数符号
    def resolve_addr(self):
        sym, offset, module = self.syms.resolve(self.addr, False)
        print(self.addr, sym, offset, module)
        self.assertEqual(offset, 0)
        self.assertTrue(module[-8:] == b'go_dummy')
        sym, offset, module = self.syms.resolve(self.addr, True)
        self.assertEqual(sym, b'main.(*T).some_function-fm')
        self.assertEqual(offset, 0)
        self.assertTrue(module[-8:] == b'go_dummy')

    # 解析函数符号=>地址
    def resolve_name(self):
        script_dir = os.path.dirname(os.path.realpath(__file__).encode("utf8"))
        addr = self.syms.resolve_name(os.path.join(script_dir, b'go_dummy'),
                                      self.mangled_name)
        self.assertEqual(addr, self.addr)
        pass

class TestDebuglinkGo(HarnessGo):
    def build_command(self):
        subprocess.check_output('go build -o go_dummy go_dummy.go'.split())
        lines = subprocess.check_output('nm go_dummy'.split()).splitlines()
        for line in lines:
            if b"some_function" in line:
                self.mangled_name = line.split(b' ')[2]
                break
        self.assertTrue(self.mangled_name)

    def debug_command(self):
        subprocess.check_output('objcopy --add-gnu-debuglink=go_dummy.debug go_dummy'.split())
        

    def tearDown(self):
        super(TestDebuglinkGo, self).tearDown()
        subprocess.check_output('rm go_dummy go_dummy.debug'.split())

    def test_resolve_addr(self):
        self.resolve_addr()

    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_resolve_name(self):
    #     self.resolve_name()

# 无法通过，因为bcc不支持.note.go.build-id
# class TestBuildidGo(HarnessGo):
#     def build_command(self):
#         subprocess.check_output("go build -o go_dummy".split() + ['-ldflags=-buildid 0x123456789abcdef0123456789abcdef012345678', 'go_dummy.go'])
#         lines = subprocess.check_output('nm go_dummy'.split()).splitlines()
#         for line in lines:
#             if b"some_function" in line:
#                 self.mangled_name = line.split(b' ')[2]
#                 break
#         self.assertTrue(self.mangled_name)


#     def debug_command(self):
#         subprocess.check_output('mkdir -p /usr/lib/debug/.build-id/12'.split())
#         subprocess.check_output(('mv go_dummy.debug /usr/lib/debug/.build-id' + \
#             '/12/3456789abcdef0123456789abcdef012345678.debug').split())

#     def tearDown(self):
#         super(TestBuildidGo, self).tearDown()
#         subprocess.check_output('rm go_dummy'.split())
#         subprocess.check_output(('rm /usr/lib/debug/.build-id/12' +
#             '/3456789abcdef0123456789abcdef012345678.debug').split())

#     def test_resolve_name(self):
#         self.resolve_addr()

    # @mayFail("This fails on github actions environment, and needs to be fixed")
    # def test_resolve_addr(self):
    #     self.resolve_name()


if __name__ == "__main__":
    main()
